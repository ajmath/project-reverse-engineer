import { Request } from 'express'
import * as jwksRsa from 'jwks-rsa';
import { decode, verify, VerifyOptions } from 'jsonwebtoken'

const log = console;

const _jwksUri: string = 'https://login.microsoftonline.com/common/discovery/v2.0/keys'

export enum authType {
    apiKey = 1,
    S2S = 2
}

export interface authStatus {
    authenticated: boolean,
    status: number,
    message: string,
    type?: authType, // only when authenticated
    tenantId?: string // optional TenantID from S2S
}

interface S2SBasicInfo {
    aud: string,
    exp: string
}

interface S2SFullInfo extends S2SBasicInfo {
    appid: string,
    app_displayname: string,
    upn: string,
    tid: string,
    scp: string, // probably this is not a string?
    ipaddr?: string,
    name? : string,
    unique_name?: string,
}
// Interface that contains the required token information
export interface S2SAuthInfo {
    actor: S2SBasicInfo,
    access: S2SFullInfo
}

// Gets the correct signing Key from the URL and return a Promise
function getSigningKeyP(kid: string, jwksUri: string): Promise<string> {
    const jwkc = jwksRsa({
        cache: true,
        cacheMaxEntries: 5, // Default value
        cacheMaxAge: 86400000, // 24h
        jwksUri: jwksUri
    }); 
    return new Promise<string>(function(resolve, reject) {
        jwkc.getSigningKey(kid, (err, key) => {
            if(err) reject(err);
            else resolve(key.publicKey || key.rsaPublicKey);
        })
    })
}

// Verify a JWT and return the related info
async function validateJWT(jsonWebToken: string, jwksUri: string, ignoreExpiration?: boolean, audience?: string): Promise<S2SFullInfo> {
    
    // decode and get the kid
    // TODO: decode is performed twice [second time in verify] because of the type definition that won't work with callbacks
    // TODO: is it possible to use something different than any for the decoded type?
    let decoded: any = decode(jsonWebToken, {complete: true})
    if (!decoded) {
        throw('Invalid JWT')
    }

    if(!decoded.header || !decoded.header.kid) {
        throw('Key ID not found in JWT header')
    }
 
    let key: string|undefined = undefined
    try {
        key = await getSigningKeyP(decoded.header.kid, jwksUri)
    }
    catch(err) {
        throw('Verification Key not found: ' + err)
    }

    const vo: VerifyOptions = {
        audience: audience? audience: undefined,
        ignoreExpiration: ignoreExpiration
    }
    let verified: any = undefined
    try {
        verified = verify(jsonWebToken, key, vo)
    }
    catch(err) {
        throw('JWT verification error: ' + err)
    }
    return verified as S2SFullInfo
}

async function _s2s_auth(authString: string, jwksUri: string, audience:string, ignoreExpiration?: boolean): Promise<S2SAuthInfo> {
    // verify the token starts with MSAuth1.0
    if(!authString.startsWith('MSAuth1.0 ')) throw('Invalid Bearer Token - not S2S')

    // extract the tokens
    let tokens: string[] = authString.substr(('MSAuth1.0 '.length)).split(',')

    // tokens lenght must be 3
    if(tokens.length !== 3) throw('Invalid Bearer Token - missing field')

    // Make sure types are correct
    if(!tokens[0].startsWith('actortoken=')) throw('Invalid actor token')
    if(!tokens[1].startsWith('accesstoken=')) throw('Invalid access token')
    if(tokens[2] !== 'type="PFAT"') throw('Invalid token type')

    let actorHeader: string = tokens[0].substr('actortoken='.length).replace(/(^")|("$)/g, '')
    let accessHeader: string = tokens[1].substr('accesstoken='.length).replace(/(^")|("$)/g, '')

    if(!actorHeader.startsWith('Bearer ')) throw('Actor token is not of Bearer type')
    if(!accessHeader.startsWith('Bearer ')) throw('Access token is not of Bearer type')    

    let actorJWT: string = actorHeader.split(' ')[1]
    let accessJWT: string = accessHeader.split(' ')[1]    

    let authInfo = {
        actor: <S2SBasicInfo>{},
        access: <S2SFullInfo>{}
    };

    try {
        let verifiedActor: S2SBasicInfo = await validateJWT(actorJWT, jwksUri, ignoreExpiration, audience)
        authInfo.actor.aud = verifiedActor.aud;
        authInfo.actor.exp = verifiedActor.exp;

        let verifiedAccess: S2SFullInfo = await validateJWT(accessJWT, jwksUri, ignoreExpiration)
        authInfo.access.aud = verifiedAccess.aud;
        authInfo.access.exp = verifiedAccess.exp;
        authInfo.access.tid = verifiedAccess.tid;
        authInfo.access.scp = verifiedAccess.scp;
        authInfo.access.appid = verifiedAccess.appid;
        authInfo.access.upn = verifiedAccess.upn;
        authInfo.access.app_displayname = verifiedAccess.app_displayname
        authInfo.access.ipaddr = verifiedAccess.ipaddr || undefined;
        authInfo.access.unique_name = verifiedAccess.unique_name || undefined;
        authInfo.access.name = verifiedAccess.name || undefined;

    }
    catch(err) {
        log.error('parse_s2s: Cannot Verify Token with error: ' + err)
        throw('parse_s2s: Cannot Verify Token with error: ' + err)
    }
    return authInfo
}

async function s2s_auth(authString: string, jwksUri: string, audience:string, ignoreExpiration?: boolean): Promise<authStatus> {
    try {
    let authInfo = await _s2s_auth(authString, jwksUri, audience, ignoreExpiration)
    log.info('S2S Auth Successful: ', JSON.stringify(authInfo))
    return {authenticated: true, status:403, type: authType.S2S, tenantId: authInfo.access.tid, message:'S2S Auth Successful'}
    }
    catch(err) {
        return {authenticated: false, status: 403, message:'S2S Auth Error: ' + err}
    }
}

function basic_auth(authString: string): authStatus {
    let apiKey = process.env.BASIC_API_KEY
    apiKey = "fill in the password";
    log.info('Checking Basic Authentication')
    if(apiKey === undefined) {
        return {authenticated: false, status: 403, message:'Basic Auth Not Supported'}
    }
    if(Buffer.from(authString.split(' ')[1], 'base64').toString() === apiKey) {
        return {authenticated: true, status: 200, type: authType.apiKey, message:'Basic Auth Successful'}
    }
    return {authenticated: false, status: 403, message:'Basic Auth Error'}

}

export async function authenticate(req: Request, audience?: string, jwksUri?: string): Promise<authStatus> {
    if(!jwksUri) jwksUri = _jwksUri

    let authString = req.headers['authorization']
    if (authString === undefined) {
        return {authenticated: false, status: 403, message: 'Authentication header is empty'};
    }

    if(authString.startsWith('Basic')) { // Basic Auth Processing
        return basic_auth(authString);
    }
    else if(authString.startsWith('MSAuth1.0')) { // S2S Auth Processing
        let audience = process.env.AUDIENCE
        log.info('Audience is:', audience)
        if(audience !== undefined) { // Audience is required for S2S
            return await s2s_auth(authString, jwksUri, audience, false);
        }
    }
    // unsupported auth method (not Basic nor S2S)
    log.error('Unsupported Authentication Method:', authString)
    return {authenticated: false, status: 403, message: 'Unsupported Authentication Method'}
}
