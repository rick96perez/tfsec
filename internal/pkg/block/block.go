package block

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/aquasecurity/tfsec/internal/pkg/schema"
	"github.com/google/uuid"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

type Block struct {
	id          string
	hclBlock    *hcl.Block
	context     *Context
	moduleBlock *Block
	expanded    bool
	cloneIndex  int
	childBlocks []*Block
	attributes  []*Attribute
	metadata    types.Metadata
}

func New(hclBlock *hcl.Block, ctx *Context, moduleBlock *Block) *Block {
	if ctx == nil {
		ctx = NewContext(&hcl.EvalContext{}, nil)
	}

	var r hcl.Range
	switch body := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		r = body.SrcRange
	default:
		r = hclBlock.DefRange
		r.End = hclBlock.Body.MissingItemRange().End
	}
	moduleName := "root"
	if moduleBlock != nil {
		moduleName = moduleBlock.FullName()
	}
	rng := types.NewRange(
		r.Filename,
		r.Start.Line,
		r.End.Line,
	)

	var parts []string
	if hclBlock.Type != "resource" {
		parts = append(parts, hclBlock.Type)
	}
	parts = append(parts, hclBlock.Labels...)
	var parent string
	if moduleBlock != nil {
		parent = moduleBlock.FullName()
	}
	ref, _ := newReference(parts, parent)

	metadata := types.NewMetadata(rng, ref)

	if moduleBlock != nil {
		metadata = metadata.WithParent(moduleBlock.Metadata())
	}

	var children Blocks
	switch body := hclBlock.Body.(type) {
	case *hclsyntax.Body:
		for _, b := range body.Blocks {
			children = append(children, New(b.AsHCLBlock(), ctx, moduleBlock))
		}
	default:
		content, _, diag := hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag == nil {
			for _, hb := range content.Blocks {
				children = append(children, New(hb, ctx, moduleBlock))
			}
		}
	}

	b := Block{
		id:          uuid.New().String(),
		context:     ctx,
		hclBlock:    hclBlock,
		moduleBlock: moduleBlock,
		childBlocks: children,
		metadata:    metadata,
	}

	for _, attr := range b.createAttributes() {
		b.attributes = append(b.attributes, NewAttribute(attr, ctx, moduleName, metadata, ref))
	}

	return &b
}

func (b *Block) ID() string {
	return b.id
}

func (b *Block) Metadata() types.Metadata {
	return b.metadata
}

func (b *Block) GetMetadata() *types.Metadata {
	m := b.Metadata()
	return &m
}

func (b *Block) GetRawValue() interface{} {
	return nil
}

func (b *Block) InjectBlock(block *Block, name string) {
	block.hclBlock.Labels = []string{}
	block.hclBlock.Type = name
	for attrName, attr := range block.Attributes() {
		b.context.Root().SetByDot(attr.Value(), fmt.Sprintf("%s.%s.%s", b.metadata.Reference().String(), name, attrName))
	}
	b.childBlocks = append(b.childBlocks, block)
}

func (b *Block) markCountExpanded() {
	b.expanded = true
}

func (b *Block) IsCountExpanded() bool {
	return b.expanded
}

func (b *Block) Clone(index cty.Value) *Block {
	var childCtx *Context
	if b.context != nil {
		childCtx = b.context.NewChild()
	} else {
		childCtx = NewContext(&hcl.EvalContext{}, nil)
	}

	cloneHCL := *b.hclBlock

	clone := New(&cloneHCL, childCtx, b.moduleBlock)
	if len(clone.hclBlock.Labels) > 0 {
		position := len(clone.hclBlock.Labels) - 1
		labels := make([]string, len(clone.hclBlock.Labels))
		for i := 0; i < len(labels); i++ {
			labels[i] = clone.hclBlock.Labels[i]
		}
		if index.IsKnown() && !index.IsNull() {
			switch index.Type() {
			case cty.Number:
				f, _ := index.AsBigFloat().Float64()
				labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], int(f))
			case cty.String:
				labels[position] = fmt.Sprintf("%s[%q]", clone.hclBlock.Labels[position], index.AsString())
			default:
				debug.Log("Invalid key type in iterable: %#v", index.Type())
				labels[position] = fmt.Sprintf("%s[%#v]", clone.hclBlock.Labels[position], index)
			}
		} else {
			labels[position] = fmt.Sprintf("%s[%d]", clone.hclBlock.Labels[position], b.cloneIndex)
		}
		clone.hclBlock.Labels = labels
	}
	indexVal, _ := gocty.ToCtyValue(index, cty.Number)
	clone.context.SetByDot(indexVal, "count.index")
	clone.markCountExpanded()
	b.cloneIndex++
	return clone
}

func (b *Block) Context() *Context {
	return b.context
}

func (b *Block) OverrideContext(ctx *Context) {
	b.context = ctx
	for _, block := range b.childBlocks {
		block.OverrideContext(ctx.NewChild())
	}
	for _, attr := range b.attributes {
		attr.ctx = ctx
	}
}

func (b *Block) Type() string {
	return b.hclBlock.Type
}

func (b *Block) Labels() []string {
	return b.hclBlock.Labels
}

func (b *Block) GetFirstMatchingBlock(names ...string) *Block {
	var returnBlock *Block
	for _, name := range names {
		childBlock := b.GetBlock(name)
		if childBlock.IsNotNil() {
			return childBlock
		}
	}
	return returnBlock
}

func (b *Block) createAttributes() hcl.Attributes {
	switch body := b.hclBlock.Body.(type) {
	case *hclsyntax.Body:
		attributes := make(hcl.Attributes)
		for _, a := range body.Attributes {
			attributes[a.Name] = a.AsHCLAttribute()
		}
		return attributes
	default:
		_, body, diag := b.hclBlock.Body.PartialContent(schema.TerraformSchema_0_12)
		if diag != nil {
			return nil
		}
		attrs, diag := body.JustAttributes()
		if diag != nil {
			return nil
		}
		return attrs
	}
}

func (b *Block) GetBlock(name string) *Block {
	var returnBlock *Block
	if b == nil || b.hclBlock == nil {
		return returnBlock
	}
	for _, child := range b.childBlocks {
		if child.Type() == name {
			return child
		}
	}
	return returnBlock
}

func (b *Block) AllBlocks() Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	return b.childBlocks
}

func (b *Block) GetBlocks(name string) Blocks {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	var results []*Block
	for _, child := range b.childBlocks {
		if child.Type() == name {
			results = append(results, child)
		}
	}
	return results
}

func (b *Block) GetAttributes() []*Attribute {
	if b == nil {
		return nil
	}
	return b.attributes
}

func (b *Block) GetAttribute(name string) *Attribute {
	if b == nil || b.hclBlock == nil {
		return nil
	}
	for _, attr := range b.attributes {
		if attr.Name() == name {
			return attr
		}
	}
	return nil
}

func (b *Block) GetNestedAttribute(name string) *Attribute {

	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	attrName := parts[len(parts)-1]

	working := b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return nil
		} else {
			working = checkBlock
		}
	}

	if working != nil {
		return working.GetAttribute(attrName)
	}

	return nil
}

// LocalName is the name relative to the current module
func (b *Block) LocalName() string {
	return b.metadata.Reference().String()
}

func (b *Block) FullName() string {

	if b.moduleBlock != nil {
		return fmt.Sprintf(
			"%s:%s",
			b.moduleBlock.FullName(),
			b.LocalName(),
		)
	}

	return b.LocalName()
}

func (b *Block) UniqueName() string {
	if b.moduleBlock != nil {
		return fmt.Sprintf("%s:%s:%s", b.FullName(), b.metadata.Range().GetFilename(), b.moduleBlock.UniqueName())
	}
	return fmt.Sprintf("%s:%s", b.FullName(), b.metadata.Range().GetFilename())
}

func (b *Block) TypeLabel() string {
	if len(b.Labels()) > 0 {
		return b.Labels()[0]
	}
	return ""
}

func (b *Block) NameLabel() string {
	if len(b.Labels()) > 1 {
		return b.Labels()[1]
	}
	return ""
}

func (b *Block) HasChild(childElement string) bool {
	return b.GetAttribute(childElement).IsNotNil() || b.GetBlock(childElement).IsNotNil()
}

func (b *Block) MissingChild(childElement string) bool {
	if b == nil {
		return true
	}

	return !b.HasChild(childElement)
}

func (b *Block) MissingNestedChild(name string) bool {
	if b == nil {
		return true
	}

	parts := strings.Split(name, ".")
	blocks := parts[:len(parts)-1]
	last := parts[len(parts)-1]

	working := b
	for _, subBlock := range blocks {
		if checkBlock := working.GetBlock(subBlock); checkBlock == nil {
			return true
		} else {
			working = checkBlock
		}
	}
	return !working.HasChild(last)

}

func (b *Block) InModule() bool {
	if b == nil {
		return false
	}
	return b.moduleBlock != nil
}

func (b *Block) Label() string {
	return strings.Join(b.hclBlock.Labels, ".")
}

func (b *Block) IsResourceType(resourceType string) bool {
	return b.TypeLabel() == resourceType
}

func (b *Block) IsEmpty() bool {
	return len(b.AllBlocks()) == 0 && len(b.GetAttributes()) == 0
}

func (b *Block) Attributes() map[string]*Attribute {
	attributes := make(map[string]*Attribute)
	for _, attr := range b.GetAttributes() {
		attributes[attr.Name()] = attr
	}
	return attributes
}

func (b *Block) Values() cty.Value {
	values := make(map[string]cty.Value)
	for _, attribute := range b.GetAttributes() {
		values[attribute.Name()] = attribute.Value()
	}
	return cty.ObjectVal(values)
}

func (b *Block) IsNil() bool {
	return b == nil
}

func (b *Block) IsNotNil() bool {
	return !b.IsNil()
}
