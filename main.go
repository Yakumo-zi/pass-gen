package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"slices"
)

var ErrSelectorExhausted = errors.New("selector exhausted")
var ErrEmptyCharSet = errors.New("empty character set")
var ErrNegativeCharSetCount = errors.New("negative character set count")
var ErrNoSelectors = errors.New("no selectors")

var lowercaseCharSet = "abcdefghijklmnopqrstuvwxyz"
var uppercaseCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
var specialCharSet = `,.;:'"?!@#$%^&*-_+=(){}[]<>`
var numberCharSet = "1234567890"

type Selector func() (byte, error)

func (s Selector) Select() (byte, error) {
	return s()
}

func SelectorFactory(chars string, count int) Selector {
	length := len(chars)
	max := big.NewInt(int64(length))
	return func() (byte, error) {
		if length == 0 {
			return 0, ErrEmptyCharSet
		}
		if count < 0 {
			return 0, ErrNegativeCharSetCount
		}
		if count == 0 {
			return 0, ErrSelectorExhausted
		}
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return 0, fmt.Errorf("generate random index: %w", err)
		}
		c := chars[r.Int64()]
		count -= 1
		return c, nil
	}
}

type PasswordGenerator struct {
	selectors []Selector
}

type Option func(*PasswordGenerator)

func WithSelector(chars string, count int) Option {
	return func(pg *PasswordGenerator) {
		pg.selectors = append(pg.selectors, SelectorFactory(chars, count))
	}
}

func NewPasswordGenerator(opts ...Option) *PasswordGenerator {
	pg := &PasswordGenerator{
		selectors: []Selector{},
	}
	for _, opt := range opts {
		opt(pg)
	}
	return pg
}

func (pg *PasswordGenerator) Generate() ([]byte, error) {
	if len(pg.selectors) == 0 {
		return []byte{}, ErrNoSelectors
	}
	pw := []byte{}
	for {
		if len(pg.selectors) == 0 {
			return pw, nil
		}
		max := big.NewInt(int64(len(pg.selectors)))
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return pw, fmt.Errorf("generate random index: %w", err)
		}
		idx := int(r.Int64())
		selector := pg.selectors[idx]
		ch, err := selector.Select()

		if err != nil {
			if errors.Is(err, ErrSelectorExhausted) {
				pg.selectors = slices.Delete(pg.selectors, idx, idx+1)
				continue
			}
			return pw, err
		}
		pw = append(pw, ch)
	}
}

type Config struct {
	LowerCount   int
	UpperCount   int
	NumberCount  int
	SpecialCount int
}

func main() {
	config := Config{}
	flag.IntVar(&config.LowerCount, "lower", 0, "lower <int>, password lower characters num")
	flag.IntVar(&config.UpperCount, "upper", 0, "upper <int>, password upper characters num")
	flag.IntVar(&config.NumberCount, "num", 0, "num <int>, password number characters num")
	flag.IntVar(&config.SpecialCount, "special", 0, "special <int>, password special characters num")
	flag.Parse()

	opts := []Option{}
	if config.LowerCount != 0 {
		opts = append(opts, WithSelector(lowercaseCharSet, config.LowerCount))
	}
	if config.UpperCount != 0 {
		opts = append(opts, WithSelector(uppercaseCharSet, config.UpperCount))
	}
	if config.NumberCount != 0 {
		opts = append(opts, WithSelector(numberCharSet, config.NumberCount))
	}
	if config.SpecialCount != 0 {
		opts = append(opts, WithSelector(specialCharSet, config.SpecialCount))
	}
	if len(opts) == 0 {
		fmt.Printf("not configure selector\n")
		return
	}
	pg := NewPasswordGenerator(
		opts...,
	)
	pw, err := pg.Generate()
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Printf("pw:%s\nlength:%d\n", string(pw), len(pw))
}
