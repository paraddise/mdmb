package diagnostics

import (
	"context"
	"fmt"
	"io"
	"log"
)

type outputKey struct{}

func WithOutput(ctx context.Context, output io.Writer) context.Context {
	return context.WithValue(ctx, outputKey{}, output)
}

func Printf(ctx context.Context, fallback io.Writer, format string, args ...any) {
	if ctx != nil {
		if output, ok := ctx.Value(outputKey{}).(io.Writer); ok {
			fmt.Fprintf(output, format, args...)
			return
		}
	}
	if fallback == nil {
		log.Printf(format, args...)
		return
	}
	fmt.Fprintf(fallback, format, args...)
}
