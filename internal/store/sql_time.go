package store

import (
	"database/sql/driver"
	"time"

	"modernc.org/sqlite"
)

func init() {
	// SQLite's date functions round fractions to milliseconds. A fixed-width UTC
	// key preserves RFC3339 offsets and nanoseconds for ordering and comparisons.
	sqlite.MustRegisterDeterministicScalarFunction("store_time_key", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		raw, _ := args[0].(string)
		stamp, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, err
		}
		return stamp.UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
	})
}
