/// Sezam vault data models — matches the desktop/web envelope schema.

/// Encryption algorithm constants (spec 2.5, 2.6).
class EnvelopeConstants {
  static const int algXChaCha20Poly1305 = 1;
  static const int schemaVersion = 1;
  static const int nonceLen = 24;
  static const int headerLen = 29; // alg(1) + schema(1) + kind(1) + dekId(26)
  static const int minEnvelopeLen = 53; // header(29) + nonce(24)
  static const int aadLen =
      59; // alg(1) + schema(1) + kind(1) + dekId(26) + objectId(26) + version(4)
  static const int dekIdLen = 26;
}

/// Blob kind identifiers (spec 2.6).
class BlobKind {
  static const int nodeMeta = 1;
  static const int entryMeta = 2;
  static const int entryData = 3;
  static const int historySnapshot = 4;
  static const int auditDetails = 5;
  static const int dekWrap = 6;
  static const int keypairWrap = 7;
}

/// A vault node (folder) after decryption.
class VaultNode {
  final String id;
  final String name;
  final String? icon;
  final String? parentRef;
  final int version;
  final bool isDeleted;
  final int? commitSeq;
  final String? dekId; // DEK named in the meta envelope header
  final bool personal; // personal folder: own DEK, no admin envelope

  const VaultNode({
    required this.id,
    required this.name,
    this.icon,
    this.parentRef,
    this.version = 1,
    this.isDeleted = false,
    this.commitSeq,
    this.dekId,
    this.personal = false,
  });

  Map<String, dynamic> toJson() => {
    'name': name,
    if (icon != null) 'icon': icon,
  };

  factory VaultNode.fromJson(
    String id,
    Map<String, dynamic> json, {
    String? parentRef,
    int version = 1,
    int? commitSeq,
    String? dekId,
  }) {
    return VaultNode(
      id: id,
      name: json['name'] as String? ?? '(unknown)',
      icon: json['icon'] as String?,
      parentRef: parentRef,
      version: version,
      commitSeq: commitSeq,
      dekId: dekId,
      personal: json['personal'] == true,
    );
  }
}

/// A vault entry (credential) after decryption.
class VaultEntry {
  final String id;
  final String name;
  final List<EntryField> fields;
  final List<String> tags;
  final String? parentRef;
  final int version;
  final bool isDeleted;
  final int? commitSeq;
  final String? notes;
  final String? ownerId;
  final String writePolicy; // 'owner_only' (creator edits) or 'shared'
  final String? accessLevel; // folder envelope ACL: 'read', 'write', or unknown
  final String? dekId; // DEK named in the payload header
  final int? tier; // desktop access tier; tier 2 has its own entry DEK

  const VaultEntry({
    required this.id,
    required this.name,
    required this.fields,
    this.tags = const [],
    this.parentRef,
    this.version = 1,
    this.isDeleted = false,
    this.commitSeq,
    this.notes,
    this.ownerId,
    this.writePolicy = 'owner_only',
    this.accessLevel,
    this.dekId,
    this.tier,
  });

  /// Ownership + folder ACL (spec 3.4): can [currentUserId] edit this entry?
  /// The server remains authoritative; this blocks read-only UI and mutations.
  bool canEdit(String? currentUserId, bool isAdmin) {
    if (isAdmin) return true;
    if (ownerId == null || ownerId!.isEmpty || ownerId == 'local') return true;
    if (ownerId == currentUserId) return true;
    return writePolicy == 'shared' && accessLevel == 'write';
  }

  Map<String, dynamic> toJson() => {
    'name': name,
    'fields': fields.map((f) => f.toJson()).toList(),
    'tags': tags,
    if (notes != null) 'notes': notes,
  };

  factory VaultEntry.fromJson(
    String id,
    Map<String, dynamic> json, {
    String? parentRef,
    int version = 1,
    int? commitSeq,
    String? ownerId,
    String writePolicy = 'owner_only',
    String? accessLevel,
    String? dekId,
  }) {
    final rawFields = json['fields'];
    List<EntryField> fields = [];
    if (rawFields is List) {
      fields = rawFields
          .map((f) => EntryField.fromJson(f as Map<String, dynamic>))
          .toList();
    }

    final rawTags = json['tags'];
    List<String> tags = [];
    if (rawTags is List) {
      tags = rawTags.map((t) => t.toString()).toList();
    }

    return VaultEntry(
      id: id,
      name: json['name'] as String? ?? '(unknown)',
      fields: fields,
      tags: tags,
      parentRef: parentRef,
      version: version,
      commitSeq: commitSeq,
      notes: json['notes'] as String?,
      ownerId: ownerId,
      writePolicy: writePolicy,
      accessLevel: accessLevel,
      dekId: dekId,
      tier: json['tier'] is int ? json['tier'] as int : null,
    );
  }
}

/// A single field within an entry.
class EntryField {
  final String key;
  final String value;
  final bool sensitive;
  final String? totp; // TOTP secret (base32) if field is a TOTP

  const EntryField({
    required this.key,
    required this.value,
    this.sensitive = false,
    this.totp,
  });

  Map<String, dynamic> toJson() => {
    'key': key,
    'value': value,
    'sensitive': sensitive,
    if (totp != null) 'totp': totp,
  };

  factory EntryField.fromJson(Map<String, dynamic> json) {
    return EntryField(
      key: json['key'] as String? ?? '',
      value: json['value'] as String? ?? '',
      sensitive: json['sensitive'] as bool? ?? false,
      totp: json['totp'] as String?,
    );
  }
}

/// A sync object as transferred to/from the server.
class SyncObject {
  final String id;
  final String objectType;
  final String payload; // base64-encoded encrypted blob
  final String? parentRef;
  final String? targetUserId;
  final int version;
  final int isDeleted;
  final String payloadHash; // SHA-256 hex
  final String signature; // Ed25519 hex

  const SyncObject({
    required this.id,
    required this.objectType,
    required this.payload,
    this.parentRef,
    this.targetUserId,
    required this.version,
    this.isDeleted = 0,
    required this.payloadHash,
    required this.signature,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'object_type': objectType,
    'payload': payload,
    if (parentRef != null) 'parent_ref': parentRef,
    if (targetUserId != null) 'target_user_id': targetUserId,
    'version': version,
    'is_deleted': isDeleted,
    'payload_hash': payloadHash,
    'signature': signature,
  };

  factory SyncObject.fromJson(Map<String, dynamic> json) {
    return SyncObject(
      id: json['id'] as String,
      objectType: json['object_type'] as String,
      payload: json['payload'] as String,
      parentRef: json['parent_ref'] as String?,
      targetUserId: json['target_user_id'] as String?,
      version: json['version'] as int,
      isDeleted: json['is_deleted'] as int? ?? 0,
      payloadHash: json['payload_hash'] as String,
      signature: json['signature'] as String? ?? '',
    );
  }
}

/// Pull response object from server.
class PullObject {
  final String id;
  final String objectType;
  final String payload; // base64
  final String ownerId;
  final String signatureUserId;
  final String writePolicy; // 'owner_only' or 'shared'
  final String? accessLevel; // envelope ACL: 'read' or 'write'
  final String? parentRef;
  final String? targetUserId;
  final int version;
  final int commitSeq;
  final int isDeleted;
  final String payloadHash;
  final String? clientSignature;
  final int modifiedAt;

  const PullObject({
    required this.id,
    required this.objectType,
    required this.payload,
    required this.ownerId,
    required this.signatureUserId,
    this.writePolicy = 'owner_only',
    this.accessLevel,
    this.parentRef,
    this.targetUserId,
    required this.version,
    required this.commitSeq,
    required this.isDeleted,
    required this.payloadHash,
    this.clientSignature,
    required this.modifiedAt,
  });

  factory PullObject.fromJson(Map<String, dynamic> json) {
    return PullObject(
      id: json['id'] as String,
      objectType: json['object_type'] as String,
      payload: json['payload'] as String,
      ownerId: json['owner_id'] as String,
      signatureUserId:
          json['signature_user_id'] as String? ?? json['owner_id'] as String,
      writePolicy: json['write_policy'] as String? ?? 'owner_only',
      accessLevel: switch (json['access_level']) {
        'read' => 'read',
        'write' => 'write',
        _ => null,
      },
      parentRef: json['parent_ref'] as String?,
      targetUserId: json['target_user_id'] as String?,
      version: json['version'] as int,
      commitSeq: json['commit_seq'] as int,
      isDeleted: json['is_deleted'] as int? ?? 0,
      payloadHash: json['payload_hash'] as String,
      clientSignature: json['client_signature'] as String?,
      modifiedAt: json['modified_at'] as int,
    );
  }
}
