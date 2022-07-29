import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';

class AWSSignature {
  Map<String, String> call({
    required String host,
    required String path,
    required String region,
    required String service,
    required String accessKey,
    required String secretKey,
    List<Map>? headers,
    List<Map>? query,
  }) {
    final datetime = _generateDatetime();
    final payloadSt = _getPayload('');
    const method = 'GET';
    final headersMap = headers ??
        [
          {'host': host},
          {'x-amz-content-sha256': payloadSt},
          {'x-amz-date': datetime}
        ];
    List<Map> queryMap = query ?? [];
    final canonicalRequest =
        _getCanonicalRequest(method, path, queryMap, headersMap, payloadSt);
    final credentialScope = _getCredentialScope(datetime, region, service);
    final signedheaders = _getSignedheaders(headersMap);
    final signature = _getSignature(datetime, credentialScope, canonicalRequest,
        region, service, secretKey);

    final authorization =
        'AWS4-HMAC-SHA256 Credential=$accessKey/$credentialScope, SignedHeaders=$signedheaders, Signature=$signature';
    return {
      'Authorization': authorization,
      'X-Amz-Content-Sha256': payloadSt,
      'X-Amz-Date': datetime,
      'Host': host,
    };
  }

  String _getSignature(
    String datetime,
    String credentialScope,
    String canonicalRequest,
    String region,
    String service,
    String secretKey,
  ) {
    final stringToSign =
        'AWS4-HMAC-SHA256\n$datetime\n$credentialScope\n$canonicalRequest';
    final kDate =
        _sign(utf8.encode('AWS4$secretKey'), datetime.substring(0, 8));
    final kRegion = _sign(kDate, region);
    final kService = _sign(kRegion, service);
    final kSigning = _sign(kService, "aws4_request");

    final signatureHMAC = _sign(kSigning, stringToSign);
    return HEX.encode(signatureHMAC);
  }

  String _generateDatetime() {
    return DateTime.now()
        .toUtc()
        .toString()
        .replaceAll(RegExp(r'\.\d*Z$'), 'Z')
        .replaceAll(RegExp(r'[:-]|\.\d{3}'), '')
        .split(' ')
        .join('T');
  }

  String _getheadersString(List<Map> headers) {
    String text = '';
    for (var element in headers) {
      String key = element.keys.elementAt(0).toLowerCase();
      String value = element.values.elementAt(0);
      text = '$text$key:$value\n';
    }
    return text;
  }

  String _getQueryString(List<Map> query) {
    if (query.isNotEmpty) {
      String text = '';
      for (var element in query) {
        String key = element.keys.elementAt(0);
        String value = element.values.elementAt(0);
        if (text.isEmpty) {
          text = key = value;
        } else {
          text = '$text&$key';
        }
      }
      return text;
    } else {
      return '';
    }
  }

  String _getSignedheaders(List<Map> headers) {
    String text = '';
    for (var element in headers) {
      String key = element.keys.elementAt(0).toLowerCase();
      if (text.isEmpty) {
        text = key;
      } else {
        text = '$text;$key';
      }
    }
    return text;
  }

  String _getCanonicalRequest(String method, String uri, List<Map> query,
      List<Map> headers, String payload) {
    String headersString = _getheadersString(headers);
    String signedheaders = _getSignedheaders(headers);
    String querySt = _getQueryString(query);

    String canonical =
        '$method\n$uri\n$querySt\n$headersString\n$signedheaders\n$payload';
    print(canonical);

    return sha256.convert(utf8.encode(canonical)).toString();
  }

  String _getCredentialScope(String datetime, String region, String service) {
    return '${datetime.substring(0, 8)}/$region/$service/aws4_request';
  }

  String _getPayload(String payload) {
    return sha256.convert(utf8.encode(payload)).toString();
  }

  List<int> _sign(List<int> key, String message) {
    final hmac = Hmac(sha256, key);
    final dig = hmac.convert(utf8.encode(message));
    return dig.bytes;
  }
}

void main() async {
  String host = 'saude-tv.s3.amazonaws.com';
  String region = 'us-east-1';
  String service = 's3';
  String accessKey = 'AKIATRFGPUANBE5JVM65';
  String secretKey = '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';
  String path =
      '/contents/62beec1d8c2d825eafa5edf3/62d0529ea9fb835efa0867c4.mp4';

  final AWSSignature sing = AWSSignature();

  final teste = sing.call(
      host: host,
      path: path,
      region: region,
      service: service,
      accessKey: accessKey,
      secretKey: secretKey);
  print(teste);
}
