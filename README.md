# Authorized Wire Authenticated Key Exchange (AWAKE) Specification v0.1.0

## Editors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)

## Authors

* [Brooklyn Zelenka](https://github.com/expede), [Fission](https://fission.codes)
* [Daniel Holmgren](https://github.com/dholms), [Bluesky](https://blueskyweb.xyz/)

# 0. Abstract

Authorized Wire Authenticated Key Exchange (AWAKE) is an [AKE](https://en.wikipedia.org/wiki/Authenticated_Key_Exchange) built on top of the [UCAN auth token](https://github.com/ucan-wg/spec). AWAKE is similar to other mutual authentication schemes, such as self-signed [mTLS](https://datatracker.ietf.org/doc/html/rfc8705), but with a focus on authorization proofs. AWAKE leverages the capability chain to prove access to some resource, validating that the requestor is communicating with a party capable of performing certain actions. This is a helpful root of trust with a well defined context when establishing a secure communications channel.

The core problem that AWAKE solves is bootstrapping a secure session on top of a public channel. Key exchanges for point-to-point communication are plentiful, but in open, trusteless protocols, rooting trust can be a barrier for ad hoc communications channels. Two common approaches are to use a trusted certificate authority, or ignore the principal and "merely" establish a point-to-point channel.

Capability-based systems have a helpful philosophy towards a third path. By emphasizing authorization over authentication, they provide a way to know something provable about what the other party "can do", even if they have no sure way of knowing "who they are". One way of phrasing this is that such an agent is "functionally equivalent to the principal in this context".

## Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

# 1 Roles

| Name      | Role                                                 |
| --------- | ---------------------------------------------------- |
| Requester | The agent opening the session                        |
| Responder | The agent being contacted by the Requester           |
| Attacker  | An attacker attempting to gain access to the channel |

## 2 Sequence

AWAKE proceeds in 4 rounds:

0. Both parties subscribe to a well-known channel
1. Requester broadcasts intent
    * a. Temporary DID
    * b. Responder authorization criterea
2. Responder establishes point-to-point session
    * a. Responder securely proves that they have sufficient rights
    * b. Responder transmits a session key via asymmetric key exchange
3. Requester authentication
    * a. Requester sends actual DID
    * b. Requester sends instance validation (e.g. UCAN or out-of-band PIN)
4. Responder sends an `ACK`

```
Attacker                 Requester                  Responder
   │                         │                          │ 
   │         Temp DID        │         Temp DID         │ (1a)
   │       Auth Criterea     │      Auth Criterea       │ (1b)
   │◄────────────────────────┼─────────────────────────►│
   │                         │                          │
   │                         │       Authorization      │ (2a)
   │                         │        Session Key       │ (2b)
   │                         │◄─────────────────────────┤
   │                         │                          │
   │                         │        Actual DID        │ (3a)
   │                         │       & Validation       │ (3b)
   │                         ├─────────────────────────►│
   │                         │                          │
   │                         │                          │
   │                         │           ACK            │ (4)
   │                         │◄─────────────────────────┤
   │                         │                          │
```

# 3. Detailed Stages

## 3.1 Subscribe to Common Channel

AWAKE begins by all parties listening on a common channel. The channel itself is unimportant: it MAY be public, broadcast to all listeners, be assynchronous, and over any transport. To reduce channel noise, it is RECOMMENDED that this channel be specific to some topic. For instance, a websocket channel on the topic`awake:did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4` MAY be used for messages about resources owned by `did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4`.

## 3.2 Requester Broadcasts Intent

**NOTE: This stage is completely in the clear.**

```
Attacker                 Requester                  Responder
   │                         │                          │ 
   │         Temp DID        │         Temp DID         │ (1a)
   │       Auth Criterea     │      Auth Criterea       │ (1b)
   │◄────────────────────────┼─────────────────────────►│
   ⋮                         ⋮                          ⋮
```

In this step, the Requester broadcasts a temporary DID, and some criterea that it extects a Responder to provide. Both pieces of information are sent in a single message. This request payload MUST be formatted as JSON and MUST contain the `did` and `caps` fields. The `caps` field MAY be an empty array.

``` javascript
{
  "awake": "init",
  "did": didKey, 
  "caps": [ ...requiredCaps ]
}
```

### 3.2.1 Temporary DID

The Requester generates a fresh 2048-bit [RSA-OAEP](https://datatracker.ietf.org/doc/html/rfc3447) key pair. This key pair MUST be referenced as a [`did:key`](https://w3c-ccg.github.io/did-method-key/) in the payload.

This "temporary DID", and MUST only be used for key exchange. It MUST NOT be used for signatures, and MUST NOT be persisted past this one session boostrap (i.e. discard after [Step 2](#33-responder-establishes-point-to-point-session)).

### 3.2.2 Authorization Criterea

FIXME FIXME FIXME what about the root onwer?

The Requester MAY also include validation criterea expected from the Responder. This MUST be passed as an array of [UCAN capabilities](https://github.com/ucan-wg/spec#23-capability). The Responder will have to prove access to these capabilties.

## 3.2.3 Example

``` javascript
{
  "awake": "init"
  "did": "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",
  "caps": [
    {
      "with": "mailto:me@example.com",
      "can: "msg/send"
    },
    {
      "with": "dns:example.com",
      "can: "crud/update"
    },
    {
      "with": "as:did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp:*",
      "can: "*"
    }
  ]
}
```

## 3.3 Responder Establishes Point-to-Point Session

Since RSA-OAEP is slow and can only hold a small amount of data, we use it to open a secured channel over AES256-GCM.

At this step, you **DO NOT KNOW** that the provider is actually our other machine, and not a person-in-the-middle 🦹‍♀️😈 You will _authenticate_ them via a capability check in the next step.

Note that there is nothing special about AES256-GCM. This key is symmetric and will be available in memory. As such, this protocol gains little from the WebCrypto API aside from potential hardware acceleration (which can be helpful against certain timings attacks).

In a future version, AES-GCM may be replaced with AES-SIV-GCM or XChaCha20-Poly1305.

The producer 💻 sends an asymmetrically encrypted AES256-GCM session key to the temporary public key that was broadcast by the consumer. The producer will ONLY respond to ONE request over this channel at a time. It is locked to the one temporary DID until the AWAKE completes successfully, is rejected, or times out. New connections MUST use new randomly generated keys temporary DIDs and AES-GCM session keys. The producer SHOULD track keys that they have already seen, and reject new requests involving them.

### **4. Session Key Negotiation over UCAN**

This step is both a "preflight" and provider authentication via UCAN.

Up to this point, Eve 🦹‍♀️ may be impersonating Alice 👩‍💻. This step proves a priori that the provider that sent the session key actually does hold the capabilities that are being requested.

Eve 🦹‍♀️ has no incentive to delegate rights other than to hide from detection. However, in this scenario where she somehow already has a valid UCAN, the game was already over. There are remedies available (revocation & rotation) were that to happen. AWAKE aims to minimize this possibility from the outset (Alice 👩‍💻 would have to agree to granting Eve 🦹‍♀️ these rights due to human error).

This step MUST NOT delegate any rights (`att = []`), but MUST include the entire proof chain that will be used in the actual credential delegation later. For the consumer, this is an _a priori_ proof that you are communicating _directly_ with an authorized machine, that has access to at least the capabilities that you are interested in.

The AES256-GCM session key MUST be included in the "facts" (`fct`) field. Since UCANs are signed, this is used to assert that the session key came directly from the authorized user.

The UCAN audience tells us that the sender intended that key for us, and no others. It is predicated on the assumption that the **provider never reuses that key** in any other channel.

In short, this step proves provides two things:

1. Proves that you are talking to a machine that does, in fact, have the correct rights that you're looking to have delegated
2. Authenticates the 256-bit AES key to make sure that the session key hasn't been tampered with

#### Example

💻 responds by broadcasting a "closed" UCAN on channel `did:key:zALICE`, encrypted with the session key. The embedded UCAN is proof that the sender does, in fact, have permissions for the account, but it does not delegate anything yet. The facts section (`fct`) includes the same session key that is used to encrypt the data on this channel.

```javascript
// A UCAN with sent to the THROWAWAY address with *no delegation*
closedUcan.claims.iss = `did:key:z${LAPTOP}`
closedUcan.claims.aud = `did:key:z${THROWAWAY}`
closedUcan.claims.fct = [..., {"sessionKey": sessonKeyAES256}]
closedUcan.claims.att = [] // i.e. MUST delegate nothing
closedUcan.claims.prf = [...proofs] // May be omited if on the root machine

closedUcan.signature = rsaSign({
  secretKey: LAPTOP_SK,
  tokenHead: closedUcan.header,
  tokenClaims: closedUcan.claims
})

// Encrypt the token
const encryptedPayload = rsaEncrypt({
  to: IPHONE_PK, 
  payload: closedUcan
})
```

Here we're _securely_ responding with a randomly generated AES256 key, embedded in the UCAN's "facts" section. Since UCANs are signed, and the audience is the recipient, we have proof this message was intended for the recipient and has not been modified along the way.

The recipient MUST validate the following:

1. The encrypted message can be decrypted by SK associated with the `ucan.aud`
2. Signature chain — from the outermost JWT signature, all the way through nested UCANs back to the root
3. The first-level proofs (EXACTLY one level above) MUST contain the permissions that you are looking to be granted (not two nested levels of \`att: \[]\`), OR be the root credential.
4. The innermost (root) issuer (`iss` field) MUST match the channel's DID (i.e. the DID that you are requesting from).

If any of the above does not match, you MUST ignore that message and start again. It's Eve's machine trying to establish a person-in-the-middle attack (PITM) 😈

### **5. PIN Validation**

Steps 1-3 establish a connection with _a requesting machine_, but not necessarily _the user's machine_. To validate that this is the correct user, we go out of band and have the human verify a code.

The requestor displays a challenge (PIN code) to the user. It sends the PIN and DID/signing key (encrypted with the AES key) over pubsub. The UCAN holder decrypts and displays this PIN to the user and asks them to confirm that it matches. If it matches, you are talking to the correct machine, and you have the DID to delegate to 🎉

If the user declines the PIN, the UCAN token holder should send a denied message to the requestor.

#### Example

📱 receives the above message and extracts the sender's DID (and thus PK). It then [verifies](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify) that the sender's PK is in the list of exchange keys found in DNS for the target username.

If PIN validation fails, you MUST ignore the message. It's Eve trying to get you to delegate rights to her 🦹‍♀️ **You MUST start over, since that channel is compromised.**

### **6. Credential Delegation**

Now that we know that the message can be trusted, the token holder creates a UCAN with delegate rights for the requestor using their DID from the most recent message. Send that UCAN and the WNFS read key (which is also an AES key) back over the pubsub channel — of course, encrypted with the AES session key.

```javascript
aesEncrypt(
  key: sessionKey,
  payload: {
  "readKey": wnfsReadKey,
  "ucan": newUcan
})
```

# FAQ

 Why RSA-OAEP?
 
The temporary key is an RSA-OAEP key due to its ubquity, including support for non-extractable private keys in the [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web\_Crypto\_API). A non-extractable key is RECOMMENDED whenever supported by the host platform.


Why not ECC?

RSA is used because it is available with a nonexportable key in browsers, is ubiquitous on all other systems, and is not considered likely backdoored (the NIST ECCs are [considered highly suspect](http://safecurves.cr.yp.to)).
