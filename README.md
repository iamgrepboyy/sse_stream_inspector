# SSE Stream Inspector

SSE Stream Inspector is a Burp Suite extension for inspecting Server-Sent Events (SSE) and streaming HTTP responses that use the `text/event-stream` format.

It helps security researchers, API testers, and developers analyze live event streams in Burp without manually parsing raw SSE payloads.

## Features

- Detects SSE responses in Burp's HTTP history, Repeater, and message editor
- Parses event stream frames into individual events
- Displays event metadata including:
  - event name
  - event ID
  - retry value
  - raw event payload
- Highlights possible sensitive data patterns such as:
  - passwords and secrets
  - bearer tokens and JWTs
  - email addresses
  - payment-card-like values
- Adds a dedicated Burp tab called "SSE Inspector"
- Lets you load a request and replay it to inspect live server responses
- Supports chunked transfer encoding by decoding chunked payloads before parsing

## Why this extension exists

SSE responses are often streamed over long-lived connections and are not always easy to read in Burp when they are delivered as continuous event data. This extension turns those raw stream payloads into a readable table so it's easier to inspect the content of each event and look for sensitive values.

## Burp Compatibility

This extension targets Burp's legacy Jython Extender API. It is designed for use as a Burp extension loaded through the Jython environment.

## Installation

1. Ensure Burp is configured to use Jython.
2. Copy `sse_stream_inspector.py` into Burp's Jython extension directory or load it via the Burp Extender UI.
3. Start Burp and load the extension.
4. The extension will register:
   - an "SSE Inspector" suite tab
   - an SSE event tab in the message editor
   - a context menu item to load requests into the SSE inspector

## Usage

### Inspect a request from Burp history

- Right-click a request in Burp Proxy/Repeater history.
- Choose "Load request in SSE Inspector".
- The request is loaded into the inspector for replay and analysis.

### Replay and inspect

- Click "Replay and inspect" after loading a request.
- The extension sends the request and parses any SSE responses it receives.
- Events are displayed in a table with details and sensitive-data warnings.

### View SSE data in the message editor

- When a response contains SSE data, Burp can open an "SSE Events" tab.
- The tab parses the response body and lists the individual events.

## Limitations

This extension uses Burp's legacy Python API, which buffers the full response before returning it. As a result:

- per-event arrival timing is not exposed by Burp
- the extension reports timing as unavailable rather than measuring exact event timestamps

## Example output

The extension displays entries like:

- Event name
- Event ID
- Retry value
- Sensitive data summary
- Full event payload

This makes it easier to identify tokens, authentication data, or other interesting values in event streams.

## License

This project is provided as-is for security testing and analysis workflows.

## Repository contents

- `sse_stream_inspector.py` — Burp extension implementation
- `README.md` — project overview and usage documentation
