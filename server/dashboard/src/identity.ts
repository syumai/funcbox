// identity.ts decodes (but does NOT verify) the display fields carried in
// the X-Funcbox-Caller-Token header funcbox's Go host sets on every request
// to this app (internal/dashboard's signCallerToken). This is safe to trust
// for DISPLAY purposes (greeting text, the "組織:" crumb, nav gating) only
// because:
//
//   - the Go dashboard hosting layer strips any client-supplied
//     X-Funcbox-Caller-Token before setting its own (mirroring
//     internal/invoke's X-Funcbox-* stripping), so this header's value on
//     any request this app's fetch() handler sees was set by funcbox's own
//     Go process, not by whoever sent the HTTP request;
//   - the security-relevant decision -- "is this really who they claim to
//     be" -- is enforced independently, in Go, on every single
//     internalAPI call (see internal/dashboard's callerToken HMAC
//     verification), not here. A guest-JS bug that fabricated a token would
//     still fail that check and get its API calls rejected; it just might
//     render a wrong name in a heading, which is not a security boundary.
export interface CallerClaims {
	uid: string;
	email: string;
	name: string;
	role: string;
	iat: number;
}

const emptyClaims: CallerClaims = { uid: "", email: "", name: "", role: "member", iat: 0 };

export function decodeCallerToken(token: string): CallerClaims {
	if (!token) return emptyClaims;
	const dot = token.indexOf(".");
	if (dot < 0) return emptyClaims;
	const payloadB64 = token.slice(0, dot);
	try {
		const json = base64UrlDecode(payloadB64);
		const claims = JSON.parse(json) as Partial<CallerClaims>;
		return {
			uid: claims.uid ?? "",
			email: claims.email ?? "",
			name: claims.name ?? "",
			role: claims.role ?? "member",
			iat: claims.iat ?? 0,
		};
	} catch {
		return emptyClaims;
	}
}

function base64UrlDecode(s: string): string {
	const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return new TextDecoder().decode(bytes);
}
