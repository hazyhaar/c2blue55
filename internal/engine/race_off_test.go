//go:build !race

package engine

// raceDetectorEnabled est faux hors instrumentation du détecteur de courses.
const raceDetectorEnabled = false
