# Session Package

A Go package that provides session management via TGM (The Graph Market)

## Overview

This package implements a session pool that manages worker connections through gRPC, providing session borrowing, keep-alive functionality and quota management.

## Features

- **Session Pooling**: Manages a pool of worker sessions with automatic lifecycle management
- **Keep-Alive**: Maintains active sessions with configurable heartbeat intervals
- **Resource Management**: Handles session borrowing and returning with proper cleanup
- **Configuration**: Flexible configuration through URL-based config strings
- **Quota Management**: Quota exhaustion detection that triggers a onError() callback
- **Shutdown**: `Close(ctx)` waits for the borrows and returns under way, then returns every session still tracked, and the pool refuses new ones. Call it right before the process exits, or a session whose return was not sent yet stays counted against the organization until it expires on the session server

## Example

See [example](../examples/tgm-session)


## Configuration

Configure via URL string with parameters:
- `insecure=true` - Skip TLS certificate verification
- `plaintext=true` - Use unencrypted connections
- `request-keep-alive-delay=30s` - Keep-alive interval
- `default-max-request-per-user=10` - Max concurrent sessions per user

Example: `tgm://session.example.com?insecure=true&request-keep-alive-delay=60s`
