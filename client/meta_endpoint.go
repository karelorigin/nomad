package client

import (
	"time"

	metrics "github.com/armon/go-metrics"
	"github.com/hashicorp/nomad/nomad/structs"
)

type NodeMeta struct {
	c *Client
}

func NewNodeMetaEndpoint(c *Client) *NodeMeta {
	n := &NodeMeta{c: c}
	return n
}

func (n *NodeMeta) Apply(req *structs.NodeMetaApplyRequest, resp *structs.NodeMetaResponse) error {
	defer metrics.MeasureSince([]string{"client", "node_meta", "apply"}, time.Now())

	newNode := c.UpdateNode(func(node *structs.Node) {
		for k, v := range args.Meta {
			if v == nil {
				delete(node.Meta, k)
				continue
			}

			node.Meta[k] = *v
		}
	})

	resp.Meta = newNode.Meta
	return nil
}

func (n *NodeMeta) Read(req *struct{}, resp *structs.NodeMetaResponse) error {
	defer metrics.MeasureSince([]string{"client", "node_meta", "reaj"}, time.Now())
	resp.Meta = n.c.Node().Meta
	return nil
}
