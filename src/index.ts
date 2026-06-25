import { Hono } from "hono";
import { authorize, callback, jwks, logout, token } from "./handlers";

const app = new Hono<{ Bindings: Env }>();

app.get("/authorize", authorize);
app.get("/callback", callback);
app.post("/token", token);
app.post("/logout", logout);
app.get("/.well-known/jwks.json", jwks);

export default app;
