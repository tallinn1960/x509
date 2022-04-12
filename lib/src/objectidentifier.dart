part of x509;

class ObjectIdentifier {
  final List<int> nodes;

  const ObjectIdentifier(this.nodes);

  ObjectIdentifier? get parent => nodes.length > 1
      ? ObjectIdentifier(nodes.take(nodes.length - 1).toList())
      : null;

  factory ObjectIdentifier.fromAsn1(ASN1ObjectIdentifier id) {
/*    var bytes = id.valueBytes();
    var nodes = <int>[];
    var v = bytes.first;
    nodes.add(v ~/ 40);
    nodes.add(v % 40);

    var w = 0;
    for (var v in bytes.skip(1)) {
      if (v >= 128) {
        w += v - 128;
        w *= 128;
      } else {
        w += v;
        nodes.add(w);
        w = 0;
      }
    }*/

    return ObjectIdentifier(id.oi);
  }

  ASN1ObjectIdentifier toAsn1() {
/*    var bytes = <int>[];
    bytes.add(nodes.first * 40 + nodes[1]);
    for (var v in nodes.skip(2)) {
      var w = <int>[];
      while (v > 128) {
        var u = v % 128;
        v -= u;
        v ~/= 128;
        w.add(u);
      }
      w.add(v);
      bytes.addAll(w.skip(1).toList().reversed.map((v) => v + 128));
      bytes.add(w.first);
    }*/
    final asn1 = ASN1ObjectIdentifier(nodes);
    // asn1.encodedBytes; // enforce encoding
    return asn1;
  }

  @override
  int get hashCode => hashObjects(nodes);

  @override
  bool operator ==(dynamic other) =>
      other is ObjectIdentifier && listsEqual(nodes, other.nodes);

  String get name {
    try {
      dynamic tree = _tree;
      for (var n in nodes) {
        tree = tree[n];
      }
      if (tree is Map) return tree[null];
      return tree;
    } catch (e) {
      throw StateError(
          'Unable to get name of ObjectIdentifier with nodes $nodes');
    }
  }

  @override
  String toString() => '$name';

  static const _tree = {
    0: {
      null: 'itu-t',
      9: {
        null: 'data',
        2342: {
          null: 'pss',
          19200300: {
            null: 'ucl',
            100: {
              null: 'pilot',
              1: {
                null: 'pilotAttributeType',
                25: {null: 'domainComponent'}
              }
            }
          }
        }
      }
    },
    1: {
      null: 'iso',
      2: {
        null: 'member-body',
        40: {
          10040: {
            null: 'x9-57',
            4: {null: 'x9cm', 1: 'dsa'}
          }
        },
        840: {
          null: 'us',
          10045: {
            null: 'ansi-X9-62',
            2: {
              null: 'keyType',
              1: 'ecPublicKey',
            },
            3: {
              null: 'curves',
              1: {
                null: 'prime',
                2: 'prime192v2',
                3: 'prime192v3',
                4: 'prime239v1',
                5: 'prime239v2',
                6: 'prime239v3',
                7: 'prime256v1',
              }
            },
            4: {
              null: 'signatures',
              3: {null: 'ecdsa-with-SHA2', 2: 'ecdsa-with-SHA256'}
            }
          },
          113549: {
            null: 'rsadsi',
            1: {
              null: 'pkcs',
              11: 'pkcs-11',
              12: 'pkcs-12',
              1: {
                null: 'pkcs-1',
                1: 'rsaEncryption',
                2: 'md2withRSAEncryption',
                4: 'md5withRSAEncryption',
                5: 'sha1WithRSAEncryption',
                6: 'rsaOAEPEncryptionSET',
                7: 'id-RSAES-OAEP',
                8: 'id-mgf1',
                9: 'id-pSpecified',
                10: 'rsassa-pss',
                11: 'sha256WithRSAEncryption',
                12: 'sha384WithRSAEncryption',
                13: 'sha512WithRSAEncryption',
                14: 'sha224WithRSAEncryption',
                15: 'sha512-224WithRSAEncryption',
                16: 'sha512-256WithRSAEncryption',
              },
              9: {
                null: 'pkcs-9',
                1: 'emailAddress',
                2: 'unstructuredName',
                3: 'contentType',
                4: 'messageDigest',
                5: 'signingTime',
                6: 'countersignature',
                7: 'challengePassword',
                8: 'unstructuredAddress',
                9: 'extendedCertificateAttributes'
              },
              3: {null: 'pkcs-3', 1: 'dhKeyAgreement'},
              7: {
                null: 'pkcs-7',
                1: 'data',
                2: 'signedData',
                3: 'envelopedData',
                4: 'signedAndEnvelopedData',
                5: 'digestData',
                6: 'encryptedData'
              }
            },
            2: {null: 'digestAlgorithm', 2: 'md2', 4: 'md4', 5: 'md5'},
            3: {
              null: 'encryptionAlgorithm',
              2: 'rc2CBC',
              4: 'rc4',
              7: 'DES-EDE3-CBC',
              8: 'RC5CBC',
              9: 'RC5CBCPAD',
              10: 'desCDMF',
              17: 'des-ede3'
            },
            5: {
              null: 'pkcs-5',
              1: 'pbeWithMD2AndDES-CBC',
              3: 'pbeWithMD5AndDES-CBC',
              11: 'pbeWithSHA1AndRC2-CBC',
              12: 'pbeWithSHA1AndRC4'
            },
            12: {
              null: 'pkcs-12',
              1: {
                null: 'pkcs-12PbeIds',
                1: 'pbeWithSHA1And128BitRC4',
                2: 'pbeWithSHA1And40BitRC4',
                3: 'pbeWithSHA1And3-KeyTripleDES-CBC',
                4: 'pbeWithSHA1And2-KeyTripleDES-CBC',
                5: 'pbeWithSHA1And128BitRC2-CBC',
                6: 'pbeWithSHA1And40BitRC2-CBC'
              }
            }
          },
          113533: {
            null: 'nt',
            7: {
              null: 'nsn',
              66: {
                null: 'algorithms',
                10: 'cast5CBC',
                11: 'cast5MAC',
                12: 'pbeWithMD5AndCAST5-CBC'
              }
            }
          }
        },
        276: {
          null: 'de',
          0: {
            null: 'din-certco',
            76: {
              null: 'gesundheitswesen',
              4: {
                null: 'idenfizierungsmechanismen',
                163: 'policy-gem-010200-or-cp',
                203: 'fd-sig'
              }
            }
          }
        }
      },
      3: {
        null: 'identified-organization',
        6: {
          null: 'dod',
          1: {
            null: 'internet',
            5: {
              null: 'security',
              5: {
                7: {
                  null: 'pkix',
                  1: {
                    null: 'pe',
                    1: 'authorityInfoAccess',
                    2: 'biometricInfo',
                    3: 'qcStatements',
                    4: 'auditIdentity',
                    5: 'id-pe-acTargeting',
                    6: 'aaControls',
                    7: {
                      null: 'id-pe-ipAddrBlocks',
                      1: 'id-acTemplate',
                      2: 'id-openPGPCertTemplateExt'
                    },
                    8: 'id-pe-autonomousSysIds',
                    9: 'id-pe-sbgp-routerIdentifier',
                    10: 'proxying',
                    11: 'subjectInfoAccess',
                    12: 'id-pe-logotype',
                    13: 'id-pe-wlanSSID',
                    14: 'id-pe-proxyCertInfo',
                    15: 'id-pe-acPolicies',
                    16: 'id-pe-warranty-extn',
                    17: 'id-pe-sim',
                    18: 'id-pe-cmsContentConstraints',
                    19: 'id-pe-otherCerts',
                    20: 'id-pe-wrappedApexContinKey',
                    21: 'id-pe-clearanceConstraints',
                    22: 'id-pe-skiSemantics',
                    23: 'id-pe-nsa',
                    24: 'ext-TLSFeatures',
                    25: 'id-pe-mud-url',
                    26: 'id-pe-TNAuthList',
                    27: 'id-pe-JWTClaimConstraints',
                    28: 'id-pe-ipAddrBlocks-v2',
                    29: 'id-pe-autonomousSysIds-v2',
                    30: 'id-pe-mudsigner',
                    31: 'id-pe-acmeIdentifier',
                    32: 'id-pe-masa-url',
                  },
                  2: {
                    null: 'qt',
                    1: 'cps',
                    2: 'unotice',
                    3: 'id-qt-textNotice',
                    4: 'id-qt-acps',
                    5: 'id-qt-acunotice'
                  },
                  3: {
                    null: 'kp',
                    1: 'serverAuth',
                    2: 'clientAuth',
                    3: 'codeSigning',
                    4: 'emailProtection',
                    8: 'timeStamping',
                    9: 'OCSPSigning'
                  }
                }
              }
            }
          }
        },
        14: {
          null: 'oiw',
          3: {
            null: 'secsig',
            2: {
              null: 'algorithm',
              2: 'md4WithRSA',
              3: 'md5WithRSA',
              4: 'md5WithRSAEncryption',
              6: 'desECB',
              7: 'desCBC',
              8: 'desOFB',
              9: 'desCFB',
              10: 'desMAC',
              11: 'RSASignature',
              12: 'DSA',
              13: 'DSAWithSHA',
              14: 'RSAWithmdc2',
              15: 'RSAWithSHA',
              16: 'dhWithCommonModulus',
              17: 'desEDE',
              18: 'SHA',
              19: 'mdc-2',
              20: 'DSACommon',
              21: 'DSACommonWithSHA',
              22: 'RSAKeyTransport',
              23: 'Keyed-hash-seal',
              24: 'md2WithRSASignature',
              25: 'md5WithRSASignature',
              26: 'SHA1',
              27: 'DSAWithSHA1',
              28: 'DSACommonWithSHA1',
              29: 'RSASignatureWithSHA1'
            }
          },
          7: {
            2: {
              1: {1: 'elGamal'},
              3: {1: 'md2WithRsa', 2: 'md2WithElGamal'}
            }
          }
        },
        36: {
          null: 'teletrust',
          3: {
            null: 'algorithm',
            1: {
              null: 'encryptionAlgorithm',
              1: {
                null: 'des',
                1: {
                  null: 'desECB',
                  1: {null: 'desECB-pad', 1: '1'}
                }
              },
              2: {
                null: '2',
                1: {
                  null: '1',
                  1: {
                    null: '1',
                    1: '1',
                  }
                },
                2: {
                  null: '2',
                  1: {null: '1', 1: '1'}
                },
                3: '3',
                4: '4'
              },
              3: {
                null: 'des-3',
                1: {
                  null: '1',
                  1: {null: '1', 1: '1'}
                },
                2: {
                  1: {null: '1', 1: '1'}
                }
              },
              4: {
                null: 'rsaEncryption',
                512: {null: '512', 17: 'rsaEncryptionWithImod512lexp17'}
              },
              5: {
                null: '5',
                1: '1',
                2: {
                  null: '2',
                  1: '1',
                }
              }
            },
            2: {
              null: 'hashAlgorithm',
              1: 'ripemd160',
              2: 'ripemd128',
              3: 'ripemd256',
              4: 'mdc2slh',
              5: 'mdc2dlh'
            },
            3: {
              null: 'signatureAlgorithm',
              1: {
                null: 'rsaSignature',
                2: 'rsaSignatureWithripemd160',
                3: 'rsaSignatureWithripemd128',
                4: 'rsaSignatureWithripemd256'
              },
              2: {
                null: 'ecSign',
                1: 'ecSignWithsha1',
                2: 'ecSignWithripemd160',
                3: 'ecSignWithmd2',
                4: 'ecSignWithmd5',
                5: {
                  null: 'ttt-ecg',
                  1: {
                    null: 'fieldType',
                    1: {
                      null: 'characteristictwoField',
                      1: {null: 'basisType', 1: 'ipBasis'}
                    }
                  },
                  2: {null: 'keyType', 1: 'ecgPublicKey'},
                  3: 'curve',
                  4: {
                    null: 'signatures',
                    1: 'ecgdsa-with-RIPEMD160',
                    2: 'ecgdsa-with-SHA1',
                    3: 'ecgdsa-with-SHA224',
                    4: 'ecgdsa-with-SHA256',
                    5: 'ecgdsa-with-SHA384',
                    6: 'ecgdsa-with-SHA512'
                  },
                  5: {
                    null: 'module',
                    1: '1',
                  }
                },
                8: {
                  null: 'ecStdCurvesAndGeneration',
                  1: {
                    null: 'ellipticCurve',
                    1: {
                      null: 'versionOne',
                      1: 'brainpoolP160r1',
                      2: 'brainpoolP160t1',
                      3: 'brainpoolP192r1',
                      4: 'brainpoolP192t1',
                      5: 'brainpoolP224r1',
                      6: 'brainpoolP224t1',
                      7: 'brainpoolP256r1',
                      8: 'brainpoolP256t1',
                      9: 'brainpoolP320r1',
                      10: 'brainpoolP320t1',
                      11: 'brainpoolP384r1',
                      12: 'brainpoolP384t1',
                      13: 'brainpoolP512r1',
                      14: 'brainpoolP512t1'
                    }
                  }
                }
              }
            },
            4: {
              null: 'signatureScheme',
              1: {null: 'sigS-ISO9796-1', 1: 'sigS-ISO9796-1-DFU'},
              2: {
                null: 'sigS-ISO9796-2',
                1: 'sigS-IOS9796-2Withred',
                2: {
                  null: 'sigS-ISO9796-2Withrsa',
                  1: 'sigS-ISO9796-2Withsha1',
                  2: 'sigS-ISO9796-2Withripemd160'
                },
                3: '3'
              },
              3: {
                null: 'sigS-ISO9796-2rnd',
                1: 'sigS-ISO9796-2rndWithrsa-even-exp',
                2: {
                  null: 'sigS-ISO9796-2rndWithrsa',
                  1: 'sigS-ISO9796-2rndWithsha1',
                  2: 'sigS-ISO9796-2rndWithripemd160',
                  3: 'sigS-ISO9796-2rndWithsha224',
                  4: 'igS-ISO9796-2rndWithsha256'
                }
              }
            },
            5: {
              null: '5',
              1: {null: 'authS-ISO9796-1', 1: 'authS-ISO9796-1-DFU'},
              2: {
                null: 'authS-ISO9796-2',
                1: 'authS-ISO9796-2Withrsa-even-exponent',
                2: {
                  null: 'authS-ISO9796-2Withrsa',
                  1: 'uthS-ISO9796-2Withsha1'
                },
                3: 'authS-ISO9796-2Withrsa-mutual'
              },
              3: {
                null: 'authS-gemSpec-COS-G2',
                1: 'authS-gemSpec-COS-G2-ecc-withsha256'
              }
            }
          },
          4: 'attribute',
          5: {
            null: 'policy',
            1: 'nici-pki',
            2: {null: 'gematik-policies', 1: 'gematik-policy-AUT-ENC-OSIG'}
          },
          8: {
            null: 'common-pki',
            1: {null: 'id-commonpki-cp', 1: '1'},
            2: {null: 'id-commonpki-kp', 1: '1'},
            3: {
              null: 'id-commonpki-at',
              1: '1',
              2: '2',
              3: 'id-isismtt-at-admission',
              4: '4',
              5: '5',
              6: '6',
              7: '7',
              8: '8',
              9: 'id-isismtt-at-retrieveIfAllowed',
              10: 'id-isismtt-at-requestedCertificate',
              11: {
                null: 'id-common-pki-namingAuthorities',
                1: {
                  null: '1',
                  1: '1',
                  2: '2',
                  3: '3',
                  4: '4',
                  5: '5',
                  6: '6',
                  7: '7',
                  8: '8',
                  9: '9',
                  10: '10',
                  11: '11',
                  12: '12',
                  13: '13',
                  14: '14',
                  15: '15',
                  16: '16',
                  17: '17',
                  18: '18',
                  19: '19'
                }
              },
              12: 'id-isismtt-at-CertInDirSince',
              13: 'id-isismtt-at-certHash',
              14: '14',
              15: '15'
            },
            4: {null: 'id-commonpki-on', 1: '1', 8: '8'},
            6: {
              null: '6',
              1: '1',
              2: '2',
              3: '3',
              4: '4',
              5: '5',
              6: '6',
              7: '7',
              8: '8',
              9: '9',
              10: '10'
            }
          },
          15: {
            null: '15',
            2: {
              null: 'gematik',
              1: {
                null: 'policy',
                1: 'sm-k',
                2: 'sm-kt',
                3: 'sm-sud',
                4: 'testbetrieb'
              },
              2: {
                null: 'admission',
                1: {
                  null: 'role',
                  1: 'apotheker',
                  2: 'arzt',
                  3: 'psychotherapeut',
                  4: 'Zahnarzt'
                },
              },
              3: {
                null: 'organisation',
                0: 'tst',
                1: {
                  null: 'le',
                  0: 'testorganisation',
                  1: 'apotheke',
                  2: 'arztpraxis',
                  3: 'krankenhaus',
                  4: 'psychotherapeutenpraxis',
                  5: 'zahnarztpraxis'
                },
                2: 'sle',
                3: 'kt'
              }
            }
          }
        },
        132: {
          null: 'certicom',
          0: {
            null: 'curve',
            1: 'sect163k1',
            2: 'sect163r1',
            3: 'sect239k1',
            4: 'sect113r1',
            5: 'sect113r2',
            6: 'secp112r1',
            7: 'secp112r2',
            8: 'secp160r1',
            9: 'secp160k1',
            10: 'secp256k1',
            15: 'sect163r2',
            16: 'sect283k1',
            17: 'sect283r1',
            22: 'sect131r1',
            23: 'sect131r2',
            24: 'sect193r1',
            25: 'sect193r2',
            26: 'sect233k1',
            27: 'sect233r1',
            28: 'secp128r1',
            29: 'secp128r2',
            30: 'secp160r2',
            31: 'secp192k1',
            32: 'secp224k1',
            33: 'secp224r1',
            34: 'secp384r1',
            35: 'secp521r1',
            36: 'sect409k1',
            37: 'sect409r1',
            38: 'sect571k1',
            39: 'sect571r1',
          }
        }
      }
    },
    2: {
      null: 'joint-iso-ccitt',
      5: {
        null: 'ds',
        4: {
          null: 'at',
          3: 'commonName',
          4: 'surname',
          5: {null: 'serialNumber', 2: 'encryptedSerialNumber'},
          6: 'countryName',
          7: 'localityName',
          8: 'stateOrProvinceName',
          10: 'organizationName',
          11: 'organizationUnitName',
          12: 'title',
          35: 'userPassword',
          36: 'userCertificate',
          37: 'cAcertificate',
          38: 'authorityRecovationList',
          39: 'certificateRevocationList',
          40: 'crossCertificatePair',
          41: 'name',
          42: 'givenName',
          43: 'initials',
          44: 'generationQualifier',
          46: 'dnQualifier',
          58: 'attributeCertificate'
        },
        8: {
          null: 'algorithm',
          1: {null: 'encryptionAlgorithm', 1: 'rsa'},
          2: 'hashAlgorithm',
          3: 'signatureAlgorithm'
        },
        29: {
          null: 'ce',
          9: 'subjectDirectoryAttributes',
          14: 'subjectKeyIdentifier',
          15: 'keyUsage',
          16: 'privateKeyUsagePeriod',
          17: 'subjectAltName',
          18: 'issuerAltName',
          19: 'basicConstraints',
          20: 'cRLNumber',
          21: 'reasonCode',
          23: 'instructionCode',
          24: 'invalidityDate',
          27: 'deltaCRLIndicator',
          28: 'issuingDistributionPoint',
          29: 'certificateIssuer',
          30: 'nameConstraints',
          31: 'cRLDistributionPoints',
          32: 'certificatePolicies',
          33: 'policyMappings',
          35: 'authorityKeyIdentifier',
          36: 'policyConstraints',
          37: 'extKeyUsage'
        }
      },
      16: {
        840: {
          1: {
            113730: {
              null: 'netscape',
              1: {
                null: 'netscape-cert-extension',
                1: 'netscape-cert-extension-type',
                2: 'netscape-base-url',
                3: 'netscape-revocation-url',
                4: 'netscape-ca-revocation-url',
                7: 'netcape-cert-renewal-url',
                8: 'netscape-policy-url',
                12: 'netscape-ssl-server-name',
                13: 'netscape-comment'
              },
              2: {null: 'netscape-data-type', 5: 'netscape-cert-sequence'}
            }
          }
        }
      },
      23: {
        null: 'international-organizations',
        140: {
          null: 'ca-browser-forum',
          1: {
            null: 'certificate-policies',
            1: 'ev-guidelines',
            2: {
              null: 'baseline-requirements',
              1: 'domain-validated',
              2: 'organization-validated',
              3: 'individual-validated'
            },
            3: '3',
            4: {
              null: 'code-signing-requirements',
              1: 'code-signing',
            },
            31: '31'
          }
        }
      },
    }
  };
}
