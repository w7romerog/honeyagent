## Descripción
<!-- Qué hace este PR y por qué es necesario -->

## Tipo de cambio
- [ ] Bug fix
- [ ] Nueva feature (honeypot, tool del agente, etc.)
- [ ] Refactor
- [ ] Documentación
- [ ] Infraestructura (Terraform)

## Tests
- [ ] Los tests unitarios existentes pasan (`pytest -m unit`)
- [ ] Se agregaron tests para el nuevo código
- [ ] Probado en modo mock (`HONEYAGENT_MOCK=true`)

## Checklist de seguridad
- [ ] No hay credenciales, API keys ni secretos en el código
- [ ] No se commitea `.env` ni `terraform.tfstate`
- [ ] Los inputs nuevos están validados en `safe_execute()`
- [ ] El IAM role de Lambda sigue el principio de mínimo privilegio
