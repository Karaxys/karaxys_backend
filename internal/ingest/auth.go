package ingest

import (
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/securetoken"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AgentRepository interface {
	FindAgentByTokenHash(tokenHash string) (core.Agent, error)
	MarkAgentSeen(agentID primitive.ObjectID) error
}

func MongoAgentAuthenticator(repo AgentRepository) AgentAuthenticator {
	return func(token string) (*AgentAuth, bool) {
		if token == "" || repo == nil {
			return nil, false
		}
		agent, err := repo.FindAgentByTokenHash(securetoken.Hash(token))
		if err != nil {
			return nil, false
		}
		_ = repo.MarkAgentSeen(agent.ID)
		return &AgentAuth{
			AgentID:      agent.ID.Hex(),
			TenantID:     agent.AccountID.Hex(),
			DataSourceID: agent.DataSourceID.Hex(),
		}, true
	}
}
