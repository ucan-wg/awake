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

AWAKE proceeds in one connecion step and four communication rounds:

1. Both parties subscribe to a well-known channel
2. Requester broadcasts intent
    * a. Temporary DID
    * b. Responder authorization criterea
3. Responder establishes point-to-point session
    * a. Responder securely proves that they have sufficient rights
    * b. Responder transmits a session key via asymmetric key exchange
4. Requester authentication
    * a. Requester sends actual DID
    * b. Requester sends instance validation (e.g. UCAN or out-of-band PIN)
5. Responder sends an `ACK`

```
Attacker                 Requester                  Responder
   │                         │                          │ 
   │         temp did        │         temp did         │ (2a)
   │       auth criterea     │      auth criterea       │ (2b)
   │◄────────────────────────┼─────────────────────────►│
   │                         │                          │
   │                         │       authorization      │ (3a)
   │                         │        session key       │ (3b)
   │                         │◄─────────────────────────┤
   │                         │                          │
   │                         │        actual did        │ (4a)
   │                         │       & validation       │ (4b)
   │                         ├─────────────────────────►│
   │                         │                          │
   │                         │                          │
   │                         │           ack            │ (5)
   │                         │◄─────────────────────────┤
   │                         │                          │
```

# 3. Detailed Stages

## 3.1 Subscribe to Common Channel

AWAKE begins by all parties listening on a common channel. The channel itself is unimportant: it MAY be public, broadcast to all listeners, be assynchronous, and over any transport. To reduce channel noise, it is RECOMMENDED that this channel be specific to some topic. For instance, a websocket channel on the topic`awake:did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4` MAY be used for messages about resources owned by `did:key:zStEZpzSMtTt9k2vszgvCwF4fLQQSyA15W5AQ4z3AR6Bx4eFJ5crJFbuGxKmbma4`.

Graceful disconnection from an AWAKE attempt can be broadcast at any step with the following payload:

``` javascript
{
  "awake": "fin", 
  "did": requestorTrueOrTempDid
}
```

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

In this step, the Requester broadcasts a temporary DID, and some criterea that it extects a Responder to provide. Both pieces of information are sent in a single message. This request payload MUST contain the `did` and `caps` fields. The `caps` field MAY be an empty array.

The payload stage MUST be signalled by the pair `"awake": "init"`.

``` javascript
{
  "awake": "init",
  "did": requesterTempDid, 
  "caps": [ ...requiredCaps ]
}
```

### 3.2.1 Temporary DID

The Requester generates a fresh 2048-bit [RSA-OAEP](https://datatracker.ietf.org/doc/html/rfc3447) key pair. This key pair MUST be referenced as a [`did:key`](https://w3c-ccg.github.io/did-method-key/) in the payload.

This "temporary DID", and MUST only be used for key exchange. It MUST NOT be used for signatures, and MUST NOT be persisted past this one session boostrap (i.e. discard after [Step 3](#33-responder-establishes-point-to-point-session)).

### 3.2.2 Authorization Criterea

The Requester MAY also include validation criterea expected from the Responder. This MUST be passed as an array of [UCAN capabilities](https://github.com/ucan-wg/spec#23-capability). The Responder will have to prove access to these capabilties.

### 3.2.3 Payload

| Field   | Value    | Purpose                                        | Required |
| --------| -------- | ---------------------------------------------- | -------- |
| `awake` | `"init"` | Signal which step of AWAKE this payload is for | Yes      |
| `did`   |          | The DID of the Requestor this is intended for  | Yes      |
| `caps`  |          | Capabilities that the Responder MUST provide   | Yes      |

#### 3.2.3.1 JSON Example

``` javascript
{
  "awake": "init"
  "did": "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",
  "caps": [
    {
      "with": "mailto:me@example.com",
      "can": "msg/send"
    },
    {
      "with": "dns:example.com",
      "can": "crud/update"
    },
    {
      "as": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
      "with": "*",
      "can": "*"
    }
  ]
}
```

## 3.3 Responder Establishes Point-to-Point Session

**NOTE: The Responder is not yet trusted at this step, and MUST be treated as a possible impersonator or PITM**

```
Requester                  Responder
    ⋮                          ⋮
    │       Authorization      │ (3a)
    │        Session Key       │ (3b)
    │◄─────────────────────────┤
    │                          │
    ⋮                          ⋮
```

In this step, the Responder MUST prove that they have access to the requested resources, and sets up a protected point-to-point connection. This is used to establish trust in the capabilities of the Responder, but MUST NOT actually delegating anything.

The temporary RSA key from the previous step MUST be exclusively used for exchanging a 256-bit AES-GCM "session key". RSA is both slow and can only hold a limited number of bytes, so using it to encrypt the payloads of the rest of the session is infeasable.

The payload contains two encryption layers, and signature: the RSA envelope, the AES envelope, and the AES key signed by the Responder.

```
          Payload

        ┌───RSA───┐
        │         │
        │ AES-GCM │
        │    │    │
        └────┼────┘
             │
             │
             ▼
┌─────────AES-GCM────────┐
│                        │
│  ┌───────UCAN───────┐  │
│  │                  │  │
│  │  iss: Responder  │  │
│  │  fct: AES-GCM    │  │
│  │  att: []         │  │
│  │  prf: ...        │  │
│  │                  │  │
│  └──────────────────┘  │
│                        │
└────────────────────────┘
```

Upon receipt, the Requestor MUST validate that the UCAN capabilities fulfill their `caps` criterea. The UCAN itself MUST be valid, unrevoked, unexpired, and intended for the temporary DID (the `aud` field). If any of these checks fail, the session MUST be abandoned, the temporary DID regenerated, and the protocol restarted from [intention braodcast](#32-requester-broadcasts-intent).

### 3.3.1 Key Exchange

The Responder MUST generate a fresh 256-bit AES-GCM key and 12-byte initialization vector (IV) per connection request. It is RECOMMENDED that the Responder track all DIDs requested with, and to only respond to each temporary DID exactly once.

The AES key MUST be encoded as padded base64 and included in the facts (`fct`) section of the payload UCAN. The rest of the [validation UCAN is constructed](#332-validation-ucan) and signed per normal, thus including the AES key in the signature payload. This signature serves as proof that the AES key was intended for this specific session.

``` javascript
{
  fct: [
    {
      "awake": base64AesKey
    }
  ]
}
```

The entire UCAN MUST be encrypted with the same AES-GCM key as included in the facts section, and using the IV before being added to the payload.

The IV MUST be generated fresh for every message in this session. If the session is not fully established, the AES key MUST NOT ever be reused.

### 3.3.2 Validation UCAN

The validation UCAN MUST NOT be used to delegate any capabilities. This UCAN MUST only be used to prove access to capabilities and sign the AES key. The `att` and `my` fields MUST be empty arrays.

### 3.3.3 Payload

| Field   | Value        | Purpose                                                     | Required |
| --------| ------------ | ----------------------------------------------------------- | -------- |
| `awake` | `"exchange"` | Signal which step of AWAKE this payload is for              | Yes      |
| `aud`   |              | The DID of the Requestor this is intended for               | Yes      |
| `key`   |              | An RSA-encrypted AES key used to encrypt the `ucan` payload | Yes      |
| `iv`    |              | Initialization vector for the encrypted `ucan` payload      | Yes      |
| `ucan`  |              | AES-encrypted validation UCAN                               | Yes      |

#### 3.3.3.1 JSON Example

``` javascript
{
  "awake": "exchange",
  "aud": requesterTempDid,
  "key": encyptedKey,
  "iv": bytes,
  "ucan":  encryptedUcan 
}
```

## 3.4. Requester Authenticates

```
Requester                  Responder
    ⋮                          ⋮
    │        actual did        │ (4a)
    │       & validation       │ (4b)
    ├─────────────────────────►│
    ⋮                          ⋮
```

``` javascript
{
  "awake": "authenticate",
  "did": trueReuqesterDid,
  // either
  "pin": outOfBandPin, // FIXME requestor specified method in previous step
  // or
  "ucan": ucan
}
```

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


Note that there is nothing special about AES256-GCM. This key is symmetric and will be available in memory. As such, this protocol gains little from the WebCrypto API aside from potential hardware acceleration (which can be helpful against certain timings attacks).

In a future version, AES-GCM may be replaced with AES-SIV-GCM or XChaCha20-Poly1305.


Eve 🦹‍♀️ has no incentive to delegate rights other than to hide from detection. However, in this scenario where she somehow already has a valid UCAN, the game was already over. There are remedies available (revocation & rotation) were that to happen. AWAKE aims to minimize this possibility from the outset (Alice 👩‍💻 would have to agree to granting Eve 🦹‍♀️ these rights due to human error).
