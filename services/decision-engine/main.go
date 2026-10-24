// Decision Engine service (Go). Consumes requests.suspicious + agent.results + labels,
// publishes decisions + weights.updates, and pushes each verdict to Redis verdict:<request_id>
// so the waiting gateway thread can answer the client.
//
//	CONFIG=../../api-threat-detection/config.json REDIS_ADDR=localhost:6379 BUS=redis go run .
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	cfg, err := LoadConfig(env("CONFIG", ""))
	if err != nil {
		log.Fatalf("config: %v", err) // FR-086: refuse to start on bad config
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})
	for i := 0; ; i++ {
		if err := rdb.Ping(ctx).Err(); err == nil {
			break
		} else if i > 30 {
			log.Fatalf("redis: %v", err)
		}
		time.Sleep(time.Second)
	}

	var bus Bus
	if env("BUS", "kafka") == "redis" {
		bus = NewRedisBus(rdb)
	} else {
		bus = NewKafkaBus(env("KAFKA_BROKERS", "localhost:9092"))
	}
	defer bus.Close()

	wm := NewWeightManager(cfg.Weights)
	if saved, err := rdb.HGetAll(ctx, "weights").Result(); err == nil && len(saved) > 0 {
		w := map[string]float64{}
		for k, v := range saved {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				w[k] = f
			}
		}
		wm.Reset(w)
		log.Printf("restored weights %v", w)
	}
	wm.OnUpdate = func(e WeightUpdate) {
		b, _ := json.Marshal(e)
		_ = bus.Publish(ctx, "weights.updates", "", b)
		if !e.Skipped {
			vals := map[string]interface{}{}
			for k, v := range e.New {
				vals[k] = v
			}
			rdb.HSet(ctx, "weights", vals)
		}
	}

	var decided atomic.Int64
	col := NewCollector(cfg, wm, func(d Decision) {
		short, _ := json.Marshal(map[string]interface{}{"verdict": d.Verdict, "score": d.Score, "degraded": d.Degraded})
		key := "verdict:" + d.RequestID
		pipe := rdb.TxPipeline()
		pipe.RPush(ctx, key, short)
		pipe.Expire(ctx, key, 30*time.Second)
		if _, err := pipe.Exec(ctx); err != nil {
			log.Printf("redis verdict %s: %v", d.RequestID, err)
		}
		full, _ := json.Marshal(d)
		if err := bus.Publish(ctx, "decisions", d.RequestID, full); err != nil {
			log.Printf("publish decision %s: %v", d.RequestID, err)
		}
		decided.Add(1)
	})

	bus.Subscribe(ctx, "requests.suspicious", "decision-engine", func(key string, v []byte) {
		var m struct {
			RequestID  string  `json:"request_id"`
			DeadlineMs float64 `json:"deadline_ms"`
		}
		if json.Unmarshal(v, &m) != nil || m.RequestID == "" {
			log.Printf("bad request event (key %s)", key)
			return
		}
		col.OnRequest(m.RequestID, json.RawMessage(v), m.DeadlineMs)
	})
	bus.Subscribe(ctx, "agent.results", "decision-engine", func(key string, v []byte) {
		var r AgentResult
		if json.Unmarshal(v, &r) != nil {
			log.Printf("bad agent result (key %s)", key)
			return
		}
		col.OnResult(r)
	})
	bus.Subscribe(ctx, "labels", "decision-engine", func(key string, v []byte) {
		var l struct {
			Label      int                `json:"label"`
			Provenance string             `json:"provenance"`
			Scores     map[string]float64 `json:"scores"`
		}
		if json.Unmarshal(v, &l) == nil && len(l.Scores) > 0 {
			if l.Provenance == "" {
				l.Provenance = "analyst"
			}
			wm.Feedback(l.Scores, l.Label, l.Provenance)
		}
	})

	go func() {
		t := time.NewTicker(5 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				col.Sweep()
			}
		}
	}()

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "pending": col.Pending(),
			"decided": decided.Load(), "weights": wm.Snapshot(), "mode": cfg.Aggregation.Mode})
	})
	srv := &http.Server{Addr: env("HTTP_ADDR", ":7003")}
	go srv.ListenAndServe()
	log.Printf("decision engine up (bus=%s, mode=%s, timeout=%v)", env("BUS", "kafka"), cfg.Aggregation.Mode, cfg.AgentTimeout())
	<-ctx.Done()
	srv.Shutdown(context.Background())
}
