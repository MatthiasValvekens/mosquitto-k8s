package topics

import (
	log "github.com/sirupsen/logrus"
	"strings"
)

const (
	AclRead      = 1
	AclWrite     = 2
	AclReadWrite = AclRead | AclWrite
	AclSubscribe = 4
)

type TopicAccess struct {
	ReadPatterns  []string
	WritePatterns []string
}

func isTopicInList(topicList []string, searchedTopic string, username string, clientid string) bool {
	log.Debugf("Checking if topic %s is in list %s", searchedTopic, strings.Join(topicList, ","))
	replacer := strings.NewReplacer("%u", username, "%c", clientid)

	for _, topicFromList := range topicList {
		if Match(replacer.Replace(topicFromList), searchedTopic) {
			return true
		}
	}
	return false
}

func (m *TopicAccess) CanRead(topic string, userName string, clientId string) bool {
	return isTopicInList(m.ReadPatterns, topic, userName, clientId)
}

func (m *TopicAccess) CanWrite(topic string, userName string, clientId string) bool {
	return isTopicInList(m.WritePatterns, topic, userName, clientId)
}

func (m *TopicAccess) CheckAccessToTopic(topic string, acc int32, userName string, clientid string) bool {
	log.Debugf("Check for acl level %d", acc)

	// TODO distinguish between read / subscribe to give the option to disallow wildcard subscriptions?

	// check read access
	if acc == AclRead || acc == AclSubscribe {
		res := m.CanRead(topic, userName, clientid)
		log.Debugf("ACL for read was %t", res)
		return res
	}

	// check write
	if acc == AclWrite {
		res := m.CanWrite(topic, userName, clientid)
		log.Debugf("ACL for write was %t", res)
		return res
	}

	// check for readwrite
	if acc == AclReadWrite {
		res := m.CanRead(topic, userName, clientid) && m.CanWrite(topic, userName, clientid)
		log.Debugf("ACL for readwrite was %t", res)
		return res
	}
	return false
}
