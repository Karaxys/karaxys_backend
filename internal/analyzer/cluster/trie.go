package cluster
import(
	"strings"
	"sync"
)

type Node struct {
	Segment  string
	Children map[string]*Node
	IsParam  bool
	IsEndpoint bool
}

type Trie struct {
	Root  *Node
	Lock  sync.RWMutex
}

func NewTrie() *Trie {
	return &Trie{
		Root: &Node{
			Children: make(map[string]*Node),
		},
	}
}

func getMergeThreshold(depth int) int{
	if depth <= 1{
		return 100
	}
	return 50
}

func (t *Trie) InsertPath(path string) (string, map[string]string){
	t.Lock.Lock()
	defer t.Lock.Unlock()
	path = strings.Trim(path, "/")
	if path == ""{
		return "/", nil
	}
	segments := strings.Split(path, "/")
	current := t.Root
	var patternParts []string
	params := make(map[string]string)

	for depth, segment := range segments {
		isVar, varName := ClassifySegment(segment)
		paramChild := t.findParamChild(current)
		if paramChild != nil && isVar{
			current = paramChild
			patternParts = append(patternParts, paramChild.Segment)
			params[paramChild.Segment] = segment
			continue
		}

		if isVar {
			if _, exists := current.Children[varName]; !exists {
				current.Children[varName] = &Node{
					Segment:  varName,
					Children: make(map[string]*Node),
					IsParam:  true,
				}
			}
			current = current.Children[varName]
			patternParts = append(patternParts, varName)
			params[varName] = segment
			continue
		}

		if _, exists := current.Children[segment]; !exists {
			current.Children[segment] = &Node{
				Segment:  segment,
				Children: make(map[string]*Node),
			}
		}
		threshold := getMergeThreshold(depth)
		if len(current.Children) >= threshold{
			t.mergeChildrenToParam(current, "{param}")
			current = current.Children["{param}"]
			patternParts = append(patternParts, "{param}")
			params["{param}"] = segment
		} else{
			current = current.Children[segment]
			patternParts = append(patternParts, segment)
		}
	}

	current.IsEndpoint = true
	return "/" + strings.Join(patternParts, "/"), params
}

func (t *Trie) findParamChild(n *Node) *Node{
	for key, child := range n.Children{
		if child.IsParam || strings.HasPrefix(key, "{"){
			return child
		}
	}
	return nil
}

func (t *Trie) mergeChildrenToParam(parent *Node, paramName string){
	if _, exists := parent.Children[paramName]; !exists{
		parent.Children[paramName] = &Node{
			Segment:  paramName,
			Children: make(map[string]*Node),
			IsParam:  true,
		}
	}

	for key := range parent.Children{
		if key != paramName{
			delete(parent.Children, key)
		}
	}
}