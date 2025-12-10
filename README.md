# Azure Function de aprovação para Copilot for Security via APIM

Esta função HTTP atua como guardião das requisições encaminhadas pelo API Management (APIM) para o Copilot for Security. Ela recebe o payload completo da chamada, aplica regras de aprovação configuráveis e responde permitindo ou negando a execução.

## Fluxo
1. O APIM envia uma requisição `POST /api/copilot/approval` com o corpo da chamada original e metadados (assinatura, produto, assinatura, operação etc.).
2. A função valida autenticação via cabeçalho `x-approval-token` (ou query `code`) comparando com a variável de ambiente `APPROVAL_TOKEN`.
3. São aplicadas regras de negócio (sensibilidade, escopos e limite de escopos) e é gerado um `decision` (`Allow` ou `Deny`).
4. Opcionalmente, o resultado é enviado para um webhook de auditoria (`AUDIT_WEBHOOK_URL`).
5. O APIM segue ou interrompe a execução conforme o `decision` retornado.

## Configuração de ambiente
Defina as variáveis abaixo no App Service da Function ou no `local.settings.json` (não comitar segredos):

- `APPROVAL_TOKEN`: token compartilhado usado pelo APIM para autenticar a chamada.
- `ALLOWED_SENSITIVITIES`: lista CSV (`low,medium,high`) de níveis de sensibilidade aceitos.
- `ALLOWED_SCOPES`: lista de escopos permitidos. Se vazia, qualquer escopo é aceito.
- `MAX_SCOPE_COUNT`: número máximo de escopos por requisição (padrão: `5`).
- `AUDIT_WEBHOOK_URL`: endpoint opcional para logging/auditoria.

Crie um `local.settings.json` (exemplo) para desenvolvimento local:

```json
{
  "IsEncrypted": false,
  "Values": {
    "FUNCTIONS_WORKER_RUNTIME": "node", 
    "APPROVAL_TOKEN": "seu-token-seguro",
    "ALLOWED_SENSITIVITIES": "low,medium,high",
    "ALLOWED_SCOPES": "Microsoft.Security/graph,Microsoft.Security/threat-hunting",
    "MAX_SCOPE_COUNT": "5",
    "AUDIT_WEBHOOK_URL": "https://sua-url-de-auditoria"
  }
}
```

## Exemplo de requisição
```bash
curl -X POST "https://<sua-function>.azurewebsites.net/api/copilot/approval?code=<function-key>" \
  -H "content-type: application/json" \
  -H "x-approval-token: seu-token-seguro" \
  -d '{
        "requestId": "123",
        "caller": "alice@contoso.com",
        "justification": "Execução de playbook",
        "sensitivity": "medium",
        "requestedScopes": ["Microsoft.Security/graph"],
        "productId": "copilot-produto",
        "subscriptionId": "sub-abc",
        "operationId": "op-001"
      }'
```

Resposta de sucesso (`Allow`):
```json
{
  "decision": "Allow",
  "requestId": "123",
  "caller": "alice@contoso.com",
  "justification": "Execução de playbook",
  "sensitivity": "medium",
  "requestedScopes": ["Microsoft.Security/graph"],
  "reason": "Aprovado automaticamente",
  "apimContext": {
    "productId": "copilot-produto",
    "subscriptionId": "sub-abc",
    "operationId": "op-001"
  },
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

Resposta de negação (`Deny`):
```json
{
  "decision": "Deny",
  "reason": "Escopos não permitidos: Microsoft.Security/graph",
  "requestId": "123",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

## Política de exemplo no APIM
Use a função como etapa de autorização no pipeline de inbound. Exemplo simplificado:

```xml
<inbound>
    <base />
    <send-request mode="new" timeout="10" response-variable-name="approvalResponse"
                  url="https://<sua-function>.azurewebsites.net/api/copilot/approval?code=@("{{function-key}}")">
        <set-header name="x-approval-token" exists-action="override">
            <value>@("{{seu-token-seguro}}")</value>
        </set-header>
        <set-header name="content-type" exists-action="override">
            <value>application/json</value>
        </set-header>
        <set-body>@(context.Request.Body.As<string>(preserveContent: true))</set-body>
    </send-request>
    <choose>
        <when condition="@(context.Variables.GetValueOrDefault<JObject>(\"approvalResponse\")?[\"decision\"]?.ToString() == \"Deny\")">
            <return-response>
                <set-status code="403" reason="Forbidden" />
                <set-body template="none">@(context.Variables.GetValueOrDefault<JObject>("approvalResponse"))</set-body>
            </return-response>
        </when>
    </choose>
</inbound>
```

## Execução local
1. Instale [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local).
2. `npm install` (caso queira adicionar dependências).
3. `func start` para rodar localmente.

A função usa Node.js 18+ e não depende de bibliotecas externas por padrão.
