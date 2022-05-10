// package logger provides a centralised logger resource
package logger

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var logged = false

func logOnce(log *logrus.Logger) {
	if logged {
		return
	}
	log.Debug("tracer hook initialising")
	logged = true
}

// Certain apps should not have mongo tracing enabled
var mgoExclusions = []string{
	
}

func isExcluded(app string) bool {
	for _, exc := range mgoExclusions {
		if app == exc {
			return true
		}
	}

	return false
}

func GetAndExcludeLoggerFromTrace(tag string) *logrus.Entry {
	for _, v := range mgoExclusions {
		if v == tag {
			return GetLogger(tag)
		}
	}

	mgoExclusions = append(mgoExclusions, tag)
	return GetLogger(tag)
}

// GetLogger will provide a tagged logger by passing in a `tag` value for easier log parsing
func GetLogger(tag string) *logrus.Entry {
	lvl := os.Getenv("TYK_MOMO_LOGLEVEL")

	var level logrus.Level
	switch strings.ToLower(lvl) {
	case "trace":
		level = logrus.TraceLevel
	case "debug":
		level = logrus.DebugLevel
	case "info":
		level = logrus.InfoLevel
	case "warning":
		level = logrus.WarnLevel
	case "error":
		level = logrus.ErrorLevel
	default:
		level = logrus.InfoLevel
	}

	logger := logrus.New()
	logger.SetLevel(level)

	// At higher log levels (debug and trace) we trade the performance hit for more details
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.ReportCaller = true
	}

	// TODO(jlucktay): add a command line flag to control this, in addition to the env var
	// ref: https://www.brandur.org/logfmt
	if os.Getenv("TYK_MOMO_LOGFMT") != "" {
		logger.SetFormatter(&logrus.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			FullTimestamp:          true,
			QuoteEmptyFields:       true,
		})
	}

	return logger.WithField("app", tag)
}
