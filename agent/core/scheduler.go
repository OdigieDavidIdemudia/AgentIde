package core

import (
	"fmt"
	"math/rand"
	"time"
)

// Profile represents the pacing strategy for an assessment.
type Profile string

const (
	ProfileRapid    Profile = "rapid"
	ProfileAPT      Profile = "apt"
	ProfileBaseline Profile = "baseline"
)

// Scheduler controls the pacing and timing of test module execution.
type Scheduler struct {
	Profile  Profile
	Days     int
	StartAt  time.Time
	StateFile string
}

// NewScheduler creates a Scheduler for the given profile and duration.
func NewScheduler(profile string, days int) *Scheduler {
	return &Scheduler{
		Profile:   Profile(profile),
		Days:      days,
		StartAt:   time.Now(),
		StateFile: "state.json",
	}
}

// ShouldRunNow returns true if the given module index is scheduled to run at this moment.
// For Rapid: always true.
// For APT: wait logic is handled fully by WaitUntilNext, so this always returns true once WaitUntilNext finishes.
// For Baseline: never run attack modules (performance monitoring only).
func (s *Scheduler) ShouldRunNow(moduleIndex, totalModules int) bool {
	switch s.Profile {
	case ProfileRapid:
		return true

	case ProfileBaseline:
		return false // Baseline never runs attack modules

	case ProfileAPT:
		if totalModules == 0 {
			return false
		}
		return true // Jitter and waiting are now fully handled in WaitUntilNext

	default:
		return true
	}
}

// WaitUntilNext blocks until the next scheduled module slot (APT mode only).
// For Rapid and Baseline, it returns immediately.
func (s *Scheduler) WaitUntilNext(moduleIndex, totalModules int) {
	if s.Profile != ProfileAPT || totalModules == 0 {
		return
	}

	totalDuration := time.Duration(s.Days) * 24 * time.Hour
	slotDuration := totalDuration / time.Duration(totalModules)
	scheduledAt := s.StartAt.Add(time.Duration(moduleIndex) * slotDuration)

	// Ensure the first module runs immediately to give user feedback
	if moduleIndex == 0 {
		return
	}

	// Add random jitter of up to 20% of the slot duration to avoid predictable patterns
	jitter := time.Duration(rand.Int63n(int64(slotDuration / 5)))
	scheduledAt = scheduledAt.Add(jitter)

	waitTime := time.Until(scheduledAt)
	if waitTime > 0 {
		fmt.Printf("[SCHEDULER] Module %d/%d scheduled in %s (including jitter)\n", moduleIndex+1, totalModules, waitTime.Round(time.Second))
		time.Sleep(waitTime)
	}
}

// ProfileDescription returns a human-readable summary of the current profile.
func (s *Scheduler) ProfileDescription() string {
	switch s.Profile {
	case ProfileRapid:
		return "Rapid-Fire — all modules run back-to-back immediately"
	case ProfileAPT:
		return fmt.Sprintf("APT / Low & Slow — modules distributed across %d day(s) with random jitter", s.Days)
	case ProfileBaseline:
		return fmt.Sprintf("Performance Baseline — CPU/RAM/network monitoring only for %d day(s)", s.Days)
	default:
		return "Unknown profile"
	}
}
