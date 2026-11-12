package web

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// scheduleIDPattern validates schedule IDs to prevent path traversal.
var scheduleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// handleSchedules handles GET /api/schedules and POST /api/schedules
func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.schedulesMu.RLock()
		defer s.schedulesMu.RUnlock()
		list := make([]*ScanSchedule, 0, len(s.schedules))
		for _, sch := range s.schedules {
			list = append(list, sch)
		}
		// Sort by Name alphabetically
		sort.Slice(list, func(i, j int) bool {
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
		_ = json.NewEncoder(w).Encode(list)
		return
	case http.MethodPost:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Targets) == 0 {
			http.Error(w, "targets are required", http.StatusBadRequest)
			return
		}
		if err := s.validateScanWebhook(req.DiscordWebhook); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			req.Name = "Scheduled Scan " + strings.Join(req.Targets, ", ")
		}
		if req.Interval == "" {
			req.Interval = "daily"
		}
		normalizeScheduleActivity(&req)
		if err := normalizeScheduleTiming(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.ID = randomSlug()
		req.Enabled = true
		req.NextRun = calculateNextRun(&req, time.Now())

		s.schedulesMu.Lock()
		s.schedules[req.ID] = &req
		diskCopy := req // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Error saving schedule to disk: %v", err)
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(req)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleScheduleDetail handles GET /api/schedules/{id}, PUT /api/schedules/{id}, DELETE /api/schedules/{id}, and POST /api/schedules/{id}/trigger
func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	path := strings.TrimPrefix(r.URL.Path, "/api/schedules/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	id := parts[0]
	if !scheduleIDPattern.MatchString(id) {
		http.Error(w, "invalid schedule id", http.StatusBadRequest)
		return
	}

	s.schedulesMu.RLock()
	sch, exists := s.schedules[id]
	s.schedulesMu.RUnlock()

	if !exists {
		http.Error(w, "schedule not found", http.StatusNotFound)
		return
	}

	// Handle trigger action
	if len(parts) > 1 && parts[1] == "trigger" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Manually trigger the scan
		req := ScanRequest{
			Targets:        sch.Targets,
			Instruction:    sch.Instruction,
			ScanMode:       sch.ScanMode,
			SeverityFilter: sch.SeverityFilter,
			Phases:         sch.Phases,
			ReconMode:      sch.ReconMode,
			ScanIntensity:  sch.ScanIntensity,
			CompanyName:    sch.CompanyName,
			LogoPath:       sch.LogoPath,
			DiscordWebhook: sch.DiscordWebhook,
			Name:           sch.Name + " (Scheduled)",
			Model:          sch.Model,
		}

		scanCfg := *s.cfg
		if sch.Model != "" {
			scanCfg.LLM = sch.Model
		}
		instanceID := randomSlug()

		go s.runMultiScan(req, &scanCfg, instanceID)

		s.schedulesMu.Lock()
		sch.LastRun = time.Now()
		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()
		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			log.Printf("[SCHEDULER] Failed to persist schedule %s after manual trigger: %v", diskCopy.ID, err)
		}

		_ = json.NewEncoder(w).Encode(map[string]string{"status": "triggered", "instance_id": instanceID})
		return
	}

	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(sch)
		return

	case http.MethodPut:
		var req ScanSchedule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if len(req.Targets) == 0 {
			http.Error(w, "targets are required", http.StatusBadRequest)
			return
		}
		if err := s.validateScanWebhook(req.DiscordWebhook); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normalizeScheduleActivity(&req)
		if err := normalizeScheduleTiming(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.schedulesMu.Lock()
		oldEnabled := sch.Enabled
		oldTiming := sch.timing()

		sch.Name = req.Name
		sch.Interval = req.Interval
		sch.RunAt = req.RunAt
		sch.RunDay = req.RunDay
		sch.Timezone = req.Timezone
		sch.Enabled = req.Enabled
		sch.Targets = req.Targets
		sch.Instruction = req.Instruction
		sch.ScanMode = req.ScanMode
		sch.SeverityFilter = req.SeverityFilter
		sch.Phases = req.Phases
		sch.ReconMode = req.ReconMode
		sch.ScanIntensity = req.ScanIntensity
		sch.CompanyName = req.CompanyName
		sch.LogoPath = req.LogoPath
		sch.DiscordWebhook = req.DiscordWebhook
		sch.Model = req.Model

		// If any timing field changed, or enabled transitioned false -> true, recalculate NextRun
		if sch.timing() != oldTiming || (sch.Enabled && !oldEnabled) {
			sch.NextRun = calculateNextRun(sch, time.Now())
		}

		diskCopy := *sch // snapshot under lock for race-free disk write
		s.schedulesMu.Unlock()

		if err := s.saveScheduleToDisk(&diskCopy); err != nil {
			http.Error(w, "failed to save schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(&diskCopy)
		return

	case http.MethodDelete:
		s.schedulesMu.Lock()
		delete(s.schedules, id)
		s.schedulesMu.Unlock()

		if err := s.deleteScheduleFromDisk(id); err != nil {
			http.Error(w, "failed to delete schedule: "+err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
