const crypto = require("crypto");

const parseCsv = (value = "") => value.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);

const sanitizeScopes = (rawScopes) => {
  if (Array.isArray(rawScopes)) {
    return rawScopes.map((scope) => String(scope).trim()).filter(Boolean);
  }
  if (typeof rawScopes === "string") {
    return rawScopes.split(",").map((scope) => scope.trim()).filter(Boolean);
  }
  return [];
};

module.exports = async function (context, req) {
  const requestId = req.body?.requestId || crypto.randomUUID();
  const authToken = req.headers["x-approval-token"] || req.query["code"];

  if (!authToken || authToken !== process.env.APPROVAL_TOKEN) {
    context.log.warn("Authorization failed for request", requestId);
    return { status: 401, body: { decision: "Deny", reason: "Invalid or missing approval token", requestId } };
  }

  if (!req.body) {
    return { status: 400, body: { decision: "Deny", reason: "Missing JSON body", requestId } };
  }

  const requiredFields = ["caller", "justification", "sensitivity", "requestedScopes"];
  const missingFields = requiredFields.filter((field) => !req.body[field]);
  if (missingFields.length) {
    return {
      status: 400,
      body: {
        decision: "Deny",
        reason: `Campos obrigatórios ausentes: ${missingFields.join(", ")}`,
        requestId,
      },
    };
  }

  const allowedSensitivities = parseCsv(process.env.ALLOWED_SENSITIVITIES || "low,medium,high");
  const allowedScopes = sanitizeScopes(process.env.ALLOWED_SCOPES || "");
  const requestedScopes = sanitizeScopes(req.body.requestedScopes);

  const denialReasons = [];

  if (!allowedSensitivities.includes(String(req.body.sensitivity).toLowerCase())) {
    denialReasons.push("Nível de sensibilidade não autorizado");
  }

  if (allowedScopes.length) {
    const unauthorizedScopes = requestedScopes.filter(
      (scope) => !allowedScopes.some((allowed) => scope.toLowerCase() === allowed.toLowerCase())
    );
    if (unauthorizedScopes.length) {
      denialReasons.push(`Escopos não permitidos: ${unauthorizedScopes.join(", ")}`);
    }
  }

  const maxScopeCount = Number(process.env.MAX_SCOPE_COUNT || "5");
  if (requestedScopes.length > maxScopeCount) {
    denialReasons.push(`Quantidade de escopos acima do limite (${maxScopeCount})`);
  }

  const decision = denialReasons.length ? "Deny" : "Allow";
  const response = {
    decision,
    requestId,
    caller: req.body.caller,
    justification: req.body.justification,
    sensitivity: req.body.sensitivity,
    requestedScopes,
    reason: denialReasons.join("; ") || "Aprovado automaticamente",
    apimContext: {
      productId: req.body.productId || null,
      subscriptionId: req.body.subscriptionId || null,
      operationId: req.body.operationId || null,
    },
    timestamp: new Date().toISOString(),
  };

  if (process.env.AUDIT_WEBHOOK_URL) {
    try {
      await fetch(process.env.AUDIT_WEBHOOK_URL, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-caller": req.body.caller,
        },
        body: JSON.stringify(response),
      });
    } catch (error) {
      context.log.warn("Não foi possível enviar log de auditoria", error.message);
    }
  }

  const status = decision === "Allow" ? 200 : 403;
  context.log.info(`Decision for request ${requestId}: ${decision}`);
  return { status, body: response };
};
