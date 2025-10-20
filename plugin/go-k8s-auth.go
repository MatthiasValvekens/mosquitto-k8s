package main

import "C"

import (
	"mosquitto-go-auth-k8s/service"
	"strings"

	log "github.com/sirupsen/logrus"
)

// errors to signal mosquitto
const (
	AuthRejected = 0
	AuthGranted  = 1
)

const version = "v0.0.2"

var authService *service.K8sAuthService

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
			log.Info("log_level unknown, using default info level")
		}
	}

	var err error

	log.SetLevel(logLevel)

	authService, err = service.NewService(authOpts)
	if err != nil {
		log.Fatalf("error initializing plugin: %s", err)
	}
	log.Infof("k8s Plugin " + version + " initialized!")
}

//export AuthUnpwdCheck
func AuthUnpwdCheck(username *C.char, password *C.char) *C.char {
	canonicalUsername := authService.Login(C.GoString(username), C.GoString(password))
	if canonicalUsername != nil {
		return C.CString(*canonicalUsername)
	} else {
		return nil
	}
}

//export AuthAclCheck
func AuthAclCheck(clientid, username, topic *C.char, acc C.int) uint8 {
	if authService.CheckAcl(C.GoString(username), C.GoString(topic), C.GoString(clientid), int32(acc)) {
		return AuthGranted
	} else {
		return AuthRejected
	}
}

func main() {}
