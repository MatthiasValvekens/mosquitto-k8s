package main

import "C"

import (
	log "github.com/sirupsen/logrus"
	"strings"
)

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
)

//export AuthPluginInit
func AuthPluginInit(keys []*C.char, values []*C.char, authOptsNum int) {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	authOpts := make(map[string]string)
	for i := 0; i < authOptsNum; i++ {
		authOpts[C.GoString(keys[i])] = C.GoString(values[i])
	}

	//Check if log level is given. Set level if any valid option is given.
	var logLevel = log.InfoLevel
	if logLevelStr, ok := authOpts["log_level"]; ok {
		logLevelStr = strings.Replace(logLevelStr, " ", "", -1)
		switch logLevelStr {
		case "debug":
			logLevel = log.DebugLevel
		case "info":
			logLevel = log.InfoLevel
		case "warn":
			logLevel = log.WarnLevel
		case "error":
			logLevel = log.ErrorLevel
		case "fatal":
			logLevel = log.FatalLevel
		case "panic":
			logLevel = log.PanicLevel
		default:
			log.Info("log_level unkwown, using default info level")
		}
	}

	var err error

	log.SetLevel(logLevel)

	err = ApplyAuthConfig(authOpts)
	if err != nil {
		log.Fatalf("error initializing backends: %s", err)
	}
}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username *C.char, password *C.char) *C.char {
	canonicalUsername := Login(C.GoString(username), C.GoString(password))
	if canonicalUsername != nil {
		return C.CString(*canonicalUsername)
	} else {
		return nil
	}
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic *C.char, acc C.int) uint8 {
	if CheckAcl(C.GoString(username), C.GoString(topic), C.GoString(clientid), int32(acc)) {
		return AuthGranted
	} else {
		return AuthRejected
	}
}

func main() {}
