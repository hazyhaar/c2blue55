package projlearn

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isDGATrainFamily reproduit la partition privée de engine.isDGATrainFamily.
func isDGATrainFamily(family string) bool {
	switch family {
	case "banjori", "emotet", "rovnix", "tinba", "Post", "ramnit", "pykspa_v1", "necurs", "qakbot", "murofet", "simda", "ranbyus", "pykspa", "shiotob/urlzone/bebloh", "gameover", "suppobox", "Volatile", "virut", "symmi":
		return true
	default:
		return false
	}
}

func corpusExample(name, family string, label float32) (Example, bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if len(name) == 0 || len(name) > 253 {
		return Example{}, false
	}
	marks := make([]int, 0, 8)
	start, longest := 0, 0
	encoded := false
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i == start || i-start > 63 {
				return Example{}, false
			}
			marks = append(marks, start, i)
			if len(marks) > 128 {
				return Example{}, false
			}
			if i-start > longest {
				longest = i - start
			}
			start = i + 1
		} else if c := name[i]; !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			encoded = true
		}
	}
	return Example{Name: []byte(name), Labels: marks, Struct: StructFeatures(1, uint8(len(marks)/2), uint8(longest), 1, encoded, len(name)), Label: label, Family: family}, true
}

func domainParent(name string) (parent, subject string, ok bool) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	last := strings.LastIndexByte(name, '.')
	if last < 1 || last == len(name)-1 {
		return "", "", false
	}
	previous := strings.LastIndexByte(name[:last], '.')
	parent = name[previous+1:]
	if previous >= 0 {
		subject = name[:previous]
	} else {
		subject = name[:last]
	}
	return parent, subject, true
}

// LoadColdSplitCorpus charge les fichiers netrack et DGA avec une partition par famille.
func LoadColdSplitCorpus(dataDir string, maxPerFamily int) (train, heldOut []Example, err error) {
	if maxPerFamily < 1 {
		return nil, nil, fmt.Errorf("borne des familles: %w", ErrCorpusContract)
	}
	// Le choix est fait au niveau de la famille, et partagé entre les deux fichiers netrack.
	side := map[string]bool{"tuns.org": true}
	quotas := make(map[string][2]int)
	benignOrder := 0
	add := func(name, family string, label float32, hold bool) {
		key := family
		if previous, exists := side[key]; exists {
			hold = previous
		} else {
			side[key] = hold
		}
		class := 0
		if label < 0 {
			class = 1
		}
		used := quotas[key]
		if used[class] >= maxPerFamily {
			return
		}
		ex, valid := corpusExample(name, family, label)
		if !valid {
			return
		}
		used[class]++
		quotas[key] = used
		if hold {
			heldOut = append(heldOut, ex)
		} else {
			train = append(train, ex)
		}
	}
	for _, relative := range []string{"netrack_dns/train.csv", "netrack_dns/test.csv", "abusayed_dga_full.csv"} {
		path := filepath.Join(dataDir, relative)
		file, openErr := os.Open(path)
		if openErr != nil {
			return nil, nil, fmt.Errorf("%w: %s: %v", ErrCorpusContract, path, openErr)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		first := true
		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r")
			if relative == "abusayed_dga_full.csv" {
				if first {
					first = false
					continue
				}
				firstComma := strings.IndexByte(line, ',')
				if firstComma < 1 {
					continue
				}
				secondComma := strings.IndexByte(line[firstComma+1:], ',')
				if secondComma < 1 {
					continue
				}
				family := line[:firstComma]
				domain := line[firstComma+1 : firstComma+1+secondComma]
				kind := line[firstComma+2+secondComma:]
				_, subject, valid := domainParent(domain)
				if !valid {
					continue
				}
				if kind == "DGA" && family != "none" {
					add(subject, family, 1, !isDGATrainFamily(family))
				}
				// Les noms normaux ont une famille parent propre, jamais la famille générique « none ».
				if kind == "Normal" {
					parent, _, _ := domainParent(domain)
					if _, exists := side[parent]; !exists {
						side[parent] = benignOrder%2 == 0
						benignOrder++
					}
					add(subject, parent, -1, side[parent])
				}
				continue
			}
			comma := strings.IndexByte(line, ',')
			if comma != 1 {
				continue
			}
			parent, subject, valid := domainParent(line[comma+1:])
			if !valid {
				continue
			}
			if line[0] == '1' {
				add(subject, parent, 1, parent == "tuns.org")
			} else if line[0] == '0' {
				if _, exists := side[parent]; !exists {
					side[parent] = benignOrder%2 == 0
					benignOrder++
				}
				add(subject, parent, -1, side[parent])
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, nil, fmt.Errorf("%w: %s: %v", ErrCorpusContract, path, scanErr)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("fermeture %s: %w", path, closeErr)
		}
	}
	return train, heldOut, nil
}
