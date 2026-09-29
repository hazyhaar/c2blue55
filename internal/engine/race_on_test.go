//go:build race

package engine

// raceDetectorEnabled signale une compilation sous détecteur de courses, dont
// l'instrumentation invalide toute mesure de latence fine.
const raceDetectorEnabled = true
