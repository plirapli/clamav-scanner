package midleware

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"scanner-service/app/scanner/service"
	"scanner-service/core/scanner/interfaces"
)

const LocalsApplicationKey = "auth.application"

type AuthMiddleware struct {
	auth interfaces.AuthService
}

func NewAuthMiddleware(auth interfaces.AuthService) AuthMiddleware {
	return AuthMiddleware{auth: auth}
}

func (m AuthMiddleware) Require() fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientID := c.Get("X-Client-Id")
		if clientID == "" {
			return writeUnauthorized(c, "client id required")
		}

		authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" || token == authHeader {
			return writeUnauthorized(c, "token required")
		}

		application, err := m.auth.Authenticate(c.UserContext(), clientID, token)
		if err != nil {
			if errors.Is(err, service.ErrInvalidClient) {
				return writeUnauthorized(c, "invalid client credentials")
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"code":    fiber.StatusInternalServerError,
				"status":  "error",
				"message": "authentication unavailable",
			})
		}

		c.Locals(LocalsApplicationKey, application)
		return c.Next()
	}
}

func writeUnauthorized(c *fiber.Ctx, message string) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"code":    fiber.StatusUnauthorized,
		"status":  "error",
		"message": message,
	})
}
