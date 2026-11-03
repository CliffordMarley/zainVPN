//go:build ignore

// mkicon draws the zainVPN logo (the orange tile with a "Z" used by both web
// UIs) into installer/zainvpn.ico. Run from the repo root:
//
//	go run installer/mkicon.go
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
)

var (
	orange = color.NRGBA{0xff, 0x99, 0x00, 0xff}
	navy   = color.NRGBA{0x23, 0x2f, 0x3e, 0xff}
)

// The logo in its 28x28 SVG coordinates: a rounded square (rx 7) and the
// "Z" polyline M8.5 9 h11 l-11 10 h11, stroked 2.6 wide with round ends.
var zPath = [][2]float64{{8.5, 9}, {19.5, 9}, {8.5, 19}, {19.5, 19}}

const (
	box    = 28.0
	radius = 7.0
	stroke = 2.6
	ss     = 8 // supersampling per axis
)

func inRoundRect(x, y float64) bool {
	cx := math.Max(radius, math.Min(box-radius, x))
	cy := math.Max(radius, math.Min(box-radius, y))
	return x >= 0 && y >= 0 && x <= box && y <= box && math.Hypot(x-cx, y-cy) <= radius
}

func onZ(x, y float64) bool {
	for i := 0; i+1 < len(zPath); i++ {
		a, b := zPath[i], zPath[i+1]
		dx, dy := b[0]-a[0], b[1]-a[1]
		t := math.Max(0, math.Min(1, ((x-a[0])*dx+(y-a[1])*dy)/(dx*dx+dy*dy)))
		if math.Hypot(x-(a[0]+t*dx), y-(a[1]+t*dy)) <= stroke/2 {
			return true
		}
	}
	return false
}

func draw(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	scale := box / float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, n float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+.5)/ss) * scale
					y := (float64(py) + (float64(sy)+.5)/ss) * scale
					if !inRoundRect(x, y) {
						continue
					}
					c := orange
					if onZ(x, y) {
						c = navy
					}
					r, g, b, n = r+float64(c.R), g+float64(c.G), b+float64(c.B), n+1
				}
			}
			if n > 0 {
				img.SetNRGBA(px, py, color.NRGBA{
					uint8(r/n + .5), uint8(g/n + .5), uint8(b/n + .5), uint8(255*n/(ss*ss) + .5),
				})
			}
		}
	}
	return img
}

// dib encodes img as an icon's BITMAPINFOHEADER + bottom-up BGRA + AND mask.
func dib(img *image.NRGBA) []byte {
	size := img.Rect.Dx()
	var buf bytes.Buffer
	maskRow := (size + 31) / 32 * 4
	binary.Write(&buf, binary.LittleEndian, struct {
		Size                         uint32
		Width, Height                int32
		Planes, BitCount             uint16
		Compression, SizeImage       uint32
		XPels, YPels, Used, Required int32
	}{40, int32(size), int32(2 * size), 1, 32, 0, uint32(size*size*4 + maskRow*size), 0, 0, 0, 0})
	for y := size - 1; y >= 0; y-- {
		for x := 0; x < size; x++ {
			c := img.NRGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	buf.Write(make([]byte, maskRow*size)) // alpha channel decides; mask all opaque
	return buf.Bytes()
}

func main() {
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 256}
	var images [][]byte
	for _, s := range sizes {
		img := draw(s)
		if s >= 256 {
			var b bytes.Buffer
			if err := png.Encode(&b, img); err != nil {
				log.Fatal(err)
			}
			images = append(images, b.Bytes())
		} else {
			images = append(images, dib(img))
		}
	}

	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))})
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		dim := uint8(s) // 256 is stored as 0
		binary.Write(&out, binary.LittleEndian, struct {
			W, H, Colors, Reserved uint8
			Planes, BitCount       uint16
			Bytes, Offset          uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(images[i])), uint32(offset)})
		offset += len(images[i])
	}
	for _, b := range images {
		out.Write(b)
	}
	if err := os.WriteFile("installer/zainvpn.ico", out.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
