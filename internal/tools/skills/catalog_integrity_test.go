package skills

import (
	"io/fs"
	"path"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEmbeddedCatalogEveryDocumentLoads(t *testing.T) {
	sub, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatal(err)
	}
	index := buildSkillIndex(sub)
	indexed := make(map[string]bool, len(index))
	for _, entry := range index {
		indexed[entry.category+"/"+entry.name] = true
	}
	count := 0
	err = fs.WalkDir(sub, ".", func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path.Base(file) != "SKILL.md" {
			return nil
		}
		parts := strings.Split(file, "/")
		if len(parts) != 3 {
			t.Errorf("skill outside catalog layout: %s", file)
			return nil
		}
		count++
		t.Run(parts[0]+"/"+parts[1], func(t *testing.T) {
			data, err := fs.ReadFile(sub, file)
			if err != nil {
				t.Fatal(err)
			}
			result, err := makeReadSkill(sub)(map[string]string{"name": parts[1], "category": parts[0]})
			if err != nil || result.Error != "" {
				t.Fatalf("read_skill: %v / %s", err, result.Error)
			}
			if result.Output != string(data) {
				t.Fatal("read_skill did not return this category's exact document")
			}
			if !indexed[parts[0]+"/"+parts[1]] {
				t.Fatal("readable document absent from search index")
			}
			sections := strings.SplitN(string(data), "---", 3)
			if len(sections) != 3 || strings.TrimSpace(sections[0]) != "" {
				t.Fatal("missing YAML frontmatter")
			}
			var metadata struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
			}
			if err := yaml.Unmarshal([]byte(sections[1]), &metadata); err != nil {
				t.Fatalf("invalid YAML frontmatter: %v", err)
			}
			if metadata.Name != parts[1] || strings.TrimSpace(metadata.Description) == "" {
				t.Fatal("frontmatter must identify the skill and explain its use")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != len(index) || count == 0 {
		t.Fatalf("catalog documents=%d index=%d", count, len(index))
	}
	t.Logf("checked %d embedded documents and exact category reads", count)
}

func TestEmbeddedCatalogEveryAliasResolves(t *testing.T) {
	sub, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatal(err)
	}
	for alias, canonical := range skillAliases {
		t.Run(alias, func(t *testing.T) {
			if _, _, ok := lookupSkill(sub, "", canonical); !ok {
				t.Fatalf("alias destination %q is absent", canonical)
			}
			result, err := makeReadSkill(sub)(map[string]string{"name": alias})
			if err != nil || result.Error != "" || result.Output == "" {
				t.Fatalf("alias load failed: %v / %s", err, result.Error)
			}
		})
	}
	t.Logf("checked %d aliases", len(skillAliases))
}
