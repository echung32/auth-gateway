export interface UserClaims {
	sub: string;
	email: string | null;
	name: string | null;
	scopes: string[];
}
