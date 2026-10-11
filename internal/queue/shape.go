package queue

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Shape is a qshape-style matrix: rows are domains, columns are age buckets in
// minutes (0-5, 5-10, 10-20 ... 1280+), cells count messages.
type Shape struct {
	Queue   string     `json:"queue"`
	By      string     `json:"by"`
	Buckets []string   `json:"buckets"`
	Total   ShapeRow   `json:"total"`
	Rows    []ShapeRow `json:"rows"`
}

// ShapeRow is one domain.
type ShapeRow struct {
	Domain string `json:"domain"`
	Total  int    `json:"total"`
	Cells  []int  `json:"cells"`
}

// BucketEdges are the upper edges in minutes, like qshape's default (-t 5 -b 10).
var BucketEdges = []int{5, 10, 20, 40, 80, 160, 320, 640, 1280}

func bucketLabels() []string {
	var out []string
	for _, e := range BucketEdges {
		out = append(out, fmt.Sprint(e))
	}
	return append(out, fmt.Sprintf("%d+", BucketEdges[len(BucketEdges)-1]))
}

func bucketOf(age time.Duration) int {
	min := age.Minutes()
	for i, e := range BucketEdges {
		if min < float64(e) {
			return i
		}
	}
	return len(BucketEdges)
}

// BuildShape computes the matrix. by is "recipient" (default) or "sender".
// A message counts once per distinct domain. top limits rows (0 = all).
func BuildShape(msgs []Message, now time.Time, queueName, by string, top int) Shape {
	if by == "" {
		by = "recipient"
	}
	nb := len(BucketEdges) + 1
	sh := Shape{Queue: queueName, By: by, Buckets: bucketLabels(), Total: ShapeRow{Domain: "TOTAL", Cells: make([]int, nb)}}
	rows := map[string]*ShapeRow{}
	for _, m := range msgs {
		if queueName != "" && queueName != "all" && m.QueueName != queueName {
			continue
		}
		b := bucketOf(now.Sub(m.Arrival()))
		sh.Total.Total++
		sh.Total.Cells[b]++
		doms := map[string]bool{}
		if by == "sender" {
			doms[Domain(m.Sender)] = true
		} else {
			for _, r := range m.Recipients {
				doms[Domain(r.Address)] = true
			}
		}
		for d := range doms {
			row := rows[d]
			if row == nil {
				row = &ShapeRow{Domain: d, Cells: make([]int, nb)}
				rows[d] = row
			}
			row.Total++
			row.Cells[b]++
		}
	}
	for _, r := range rows {
		sh.Rows = append(sh.Rows, *r)
	}
	sort.Slice(sh.Rows, func(i, j int) bool {
		if sh.Rows[i].Total != sh.Rows[j].Total {
			return sh.Rows[i].Total > sh.Rows[j].Total
		}
		return sh.Rows[i].Domain < sh.Rows[j].Domain
	})
	if top > 0 && len(sh.Rows) > top {
		sh.Rows = sh.Rows[:top]
	}
	return sh
}

// Text renders the matrix like qshape does.
func (s Shape) Text() string {
	w := 6
	for _, r := range s.Rows {
		if len(r.Domain) > w {
			w = len(r.Domain)
		}
	}
	if w > 40 {
		w = 40
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%*s %6s", w, "", "T")
	for _, l := range s.Buckets {
		fmt.Fprintf(&b, " %5s", l)
	}
	b.WriteString("\n")
	row := func(r ShapeRow) {
		d := r.Domain
		if len(d) > w {
			d = d[:w-1] + "…"
		}
		fmt.Fprintf(&b, "%*s %6d", w, d, r.Total)
		for _, c := range r.Cells {
			fmt.Fprintf(&b, " %5d", c)
		}
		b.WriteString("\n")
	}
	row(s.Total)
	for _, r := range s.Rows {
		row(r)
	}
	return b.String()
}
