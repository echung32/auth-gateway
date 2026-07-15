import { Hono } from "hono";
import { corsPreflight } from "./cors";
import {
	authorize,
	callback,
	createClientHandler,
	deleteClientHandler,
	jwks,
	listClientsHandler,
	logout,
	token,
} from "./handlers";

const app = new Hono<{ Bindings: Env }>();

app.get("/authorize", authorize);
app.get("/callback", callback);
app.options("/token", corsPreflight);
app.options("/logout", corsPreflight);
app.post("/token", token);
app.post("/logout", logout);
app.get("/.well-known/jwks.json", jwks);
app.post("/clients", createClientHandler);
app.get("/clients", listClientsHandler);
app.delete("/clients/:id", deleteClientHandler);

export default app;
export { RefreshFamily } from "./refreshFamily";
