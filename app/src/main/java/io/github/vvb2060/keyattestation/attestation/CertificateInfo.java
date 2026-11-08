package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import io.github.vvb2060.keyattestation.AppApplication;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import io.github.vvb2060.keyattestation.AppApplication;

public class CertificateInfo {
    public static final int CERT_UNKNOWN = 0;
    public static final int CERT_SIGN = 1;
    public static final int CERT_REVOKED = 2;
    public static final int CERT_EXPIRED = 3;
    public static final int CERT_NORMAL = 4;

    private final X509Certificate cert;
    private RootPublicKey.Status issuer = RootPublicKey.Status.UNKNOWN;
    private int status = CERT_UNKNOWN;
    private GeneralSecurityException securityException;
    private Attestation attestation;
    private CertificateParsingException certException;

    private ProvisioningInfo provisioningInfo;

    private CertificateInfo(X509Certificate cert) {
        this.cert = cert;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public RootPublicKey.Status getIssuer() {
        return issuer;
    }

    public int getStatus() {
        return status;
    }

    public GeneralSecurityException getSecurityException() {
        return securityException;
    }

    public Attestation getAttestation() {
        return attestation;
    }

    public CertificateParsingException getCertException() {
        return certException;
    }

    public ProvisioningInfo getProvisioningInfo() {
        return provisioningInfo;
    }

    private void checkIssuer() {
    var publicKey = cert.getPublicKey().getEncoded();
    if (Arrays.equals(publicKey, googleKey)) {
        issuer = KEY_GOOGLE;
    } else if (Arrays.equals(publicKey, aospEcKey)) {
        issuer = KEY_AOSP;
    }
    // 原有的其他判断保持不变...

    // 动态热更新：如果未匹配，尝试读取手机专属目录下的 roots.pem
    if (issuer == KEY_UNKNOWN) {
        try {
            File extDir = AppApplication.app.getExternalFilesDir(null);
            File customRoots = new File(extDir, "roots.pem");
            if (customRoots.exists() && customRoots.isFile()) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                try (InputStream fis = new FileInputStream(customRoots)) {
                    Collection<?> certList = cf.generateCertificates(fis);
                    for (Object obj : certList) {
                        if (obj instanceof X509Certificate) {
                            X509Certificate rootCert = (X509Certificate) obj;
                            if (Arrays.equals(rootCert.getPublicKey().getEncoded(), publicKey)) {
                                issuer = KEY_GOOGLE;
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }
}

    private void checkStatus(PublicKey parentKey) {
        try {
            status = CERT_SIGN;
            cert.verify(parentKey);
            status = CERT_REVOKED;
            var certStatus = RevocationList.get(cert.getSerialNumber());
            if (certStatus != null) {
                throw new CertificateException("Certificate revocation " + certStatus);
            }
            status = CERT_EXPIRED;
            cert.checkValidity();
            status = CERT_NORMAL;
        } catch (GeneralSecurityException e) {
            Log.e(AppApplication.TAG, "checkStatus", e);
            securityException = e;
        }
    }

    private boolean checkAttestation() {
        boolean terminate;
        try {
            attestation = Attestation.loadFromCertificate(cert);
            // If key purpose included KeyPurpose::SIGN,
            // then it could be used to sign arbitrary data, including any tbsCertificate,
            // and so an attestation produced by the key would have no security properties.
            // If the parent certificate can attest that the key purpose is only KeyPurpose::ATTEST_KEY,
            // then the child certificate can be trusted.
            var purposes = attestation.getTeeEnforced().getPurposes();
            terminate = purposes == null || !purposes.contains(AuthorizationList.KM_PURPOSE_ATTEST_KEY);
        } catch (CertificateParsingException e) {
            certException = e;
            terminate = false;
            provisioningInfo = ProvisioningInfo.get(cert);
        }
        return terminate;
    }

    public static void parse(List<X509Certificate> certs, List<CertificateInfo> infoList) {
        var parent = certs.get(certs.size() - 1);
        for (int i = certs.size() - 1; i >= 0; i--) {
            var parentKey = parent.getPublicKey();
            var info = new CertificateInfo(certs.get(i));
            infoList.add(info);
            info.checkStatus(parentKey);
            if (parent == info.cert) {
                info.checkIssuer();
            } else {
                parent = info.cert;
            }
            if (info.checkAttestation()) {
                break;
            }
        }
    }
}
//test
