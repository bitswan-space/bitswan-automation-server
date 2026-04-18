package config

import (
	"fmt"
	"math/rand"
)

// Docker-style random name generation: adjective-noun
var adjectives = []string{
	"bold", "bright", "calm", "cool", "eager", "fair", "fast", "keen",
	"kind", "neat", "proud", "quick", "sharp", "smart", "swift", "warm",
	"brave", "clever", "daring", "gentle", "happy", "jolly", "lively",
	"merry", "noble", "plucky", "ready", "steady", "witty", "zen",
}

var nouns = []string{
	"falcon", "heron", "osprey", "condor", "eagle", "hawk", "raven",
	"sparrow", "finch", "crane", "stork", "wren", "robin", "swift",
	"lark", "dove", "owl", "kite", "tern", "ibis", "puffin", "rail",
	"pipit", "grebe", "shrike", "vireo", "oriole", "cedar", "maple",
}

// GenerateRandomName produces a Docker-style random name like "bold-falcon".
func GenerateRandomName() string {
	adj := adjectives[rand.Intn(len(adjectives))]
	noun := nouns[rand.Intn(len(nouns))]
	return fmt.Sprintf("%s-%s", adj, noun)
}
