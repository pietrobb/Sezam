import 'dart:async';

import 'package:http/http.dart' as http;

/// Default deadline for every Sezam HTTP call. Without it a dead TCP
/// connection (captive portal, server behind a dropped NAT entry) leaves sync
/// or unlock spinning forever.
const sezamHttpTimeout = Duration(seconds: 30);

/// Fails a request that gets no response headers within [timeout], and a
/// response body that stalls for longer than [timeout] between chunks.
class TimeoutClient extends http.BaseClient {
  TimeoutClient(this._inner, {this.timeout = sezamHttpTimeout});

  final http.Client _inner;
  final Duration timeout;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await _inner.send(request).timeout(timeout);
    return http.StreamedResponse(
      response.stream.timeout(timeout),
      response.statusCode,
      contentLength: response.contentLength,
      request: response.request,
      headers: response.headers,
      isRedirect: response.isRedirect,
      persistentConnection: response.persistentConnection,
      reasonPhrase: response.reasonPhrase,
    );
  }

  @override
  void close() => _inner.close();
}
