"""
Explainable AI Module for Phishing Detection
Uses SHAP TreeExplainer; falls back to heuristic importance if SHAP fails.
Handles both old SHAP (<0.40, returns list) and new SHAP (>=0.41, returns 3D ndarray).
"""

import numpy as np
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64
from io import BytesIO


FEATURE_DISPLAY_NAMES = [
    'Using IP Address',
    'Long URL',
    'Short URL',
    'Symbol @',
    'Redirecting //',
    'Prefix/Suffix -',
    'Sub Domains',
    'HTTPS Protocol',
    'Domain Registration Length',
    'Favicon',
    'Non-Standard Port',
    'HTTPS in Domain URL',
    'Request URL',
    'Anchor URL',
    'Links in Script Tags',
    'Server Form Handler',
    'Info Email',
    'Abnormal URL',
    'Website Forwarding',
    'Status Bar Customization',
    'Disable Right Click',
    'Using Popup Window',
    'Iframe Redirection',
    'Age of Domain',
    'DNS Recording',
    'Website Traffic',
    'Page Rank',
    'Google Index',
    'Links Pointing to Page',
    'Statistical Report',
]

FEATURE_DESCRIPTIONS = {
    'Using IP Address':           'URL uses IP address instead of domain name',
    'Long URL':                   'URL length is suspiciously long',
    'Short URL':                  'Uses URL shortening service',
    'Symbol @':                   'Contains @ symbol in URL',
    'Redirecting //':             'Contains multiple // redirections',
    'Prefix/Suffix -':            'Domain has suspicious hyphens',
    'Sub Domains':                'Number of subdomains',
    'HTTPS Protocol':             'Uses secure HTTPS protocol',
    'Domain Registration Length': 'Domain name length',
    'Favicon':                    'Favicon loaded from different domain',
    'Non-Standard Port':          'Uses non-standard port number',
    'HTTPS in Domain URL':        'HTTPS token in domain name',
    'Request URL':                'External objects loaded from different domain',
    'Anchor URL':                 'Suspicious or empty anchor href attributes',
    'Links in Script Tags':       'Scripts loading from external domains',
    'Server Form Handler':        'Form submission to external/blank domain',
    'Info Email':                 'Contact email present in URL',
    'Abnormal URL':               'URL differs from WHOIS domain',
    'Website Forwarding':         'Multiple HTTP redirections detected',
    'Status Bar Customization':   'JavaScript manipulates browser status bar',
    'Disable Right Click':        'Right-click disabled via JavaScript',
    'Using Popup Window':         'Page opens popup windows',
    'Iframe Redirection':         'Contains hidden iframe redirections',
    'Age of Domain':              'Domain registration age',
    'DNS Recording':              'DNS record exists for this domain',
    'Website Traffic':            'Estimated website traffic/popularity',
    'Page Rank':                  'Google PageRank score',
    'Google Index':               'Domain appears in Google search index',
    'Links Pointing to Page':     'Number of backlinks to this page',
    'Statistical Report':         'Analytics scripts / suspicious TLD present',
}

# Features where value=1 is suspicious (for heuristic fallback)
SUSPICIOUS_ON_ONE = {
    'Using IP Address', 'Long URL', 'Short URL', 'Symbol @',
    'Redirecting //', 'Prefix/Suffix -', 'Non-Standard Port',
    'Iframe Redirection', 'Using Popup Window', 'Disable Right Click',
    'HTTPS in Domain URL', 'Info Email',
}


class PhishingExplainer:

    def __init__(self, model, feature_names):
        self.model        = model
        self.feature_names = list(feature_names)   # technical names
        self.n_features   = len(feature_names)
        self.explainer    = None

        try:
            self.explainer = shap.TreeExplainer(model)
            print(f"  [Explainer] SHAP TreeExplainer ready ({self.n_features} features).")
        except Exception as e:
            print(f"  [Explainer] SHAP init failed ({e}); will use heuristic fallback.")

    # ── Public ────────────────────────────────────────────────────────────────

    def explain_prediction(self, features: list, prediction: int) -> dict | None:
        try:
            features = list(features)[:self.n_features]
            X        = np.array(features, dtype=float).reshape(1, -1)

            display_names = FEATURE_DISPLAY_NAMES[:self.n_features]

            explanation = {
                'feature_values':     {},
                'feature_importance': {},
                'top_features':       [],
                'shap_values':        None,
                'chart_base64':       None,
            }

            for disp, val in zip(display_names, features):
                explanation['feature_values'][disp] = {
                    'value':          int(val),
                    'description':    FEATURE_DESCRIPTIONS.get(disp, ''),
                    'interpretation': self._interpret(disp, val),
                }

            importance, shap_raw = self._compute_importance(X, display_names)
            if shap_raw is not None:
                explanation['shap_values'] = shap_raw.tolist()

            total = sum(importance.values()) or 1.0
            importance_norm = {k: v / total for k, v in importance.items()}

            sorted_feats = sorted(importance_norm.items(), key=lambda x: x[1], reverse=True)

            explanation['feature_importance'] = dict(sorted_feats)
            explanation['top_features'] = [
                {
                    'name':           name,
                    'importance':     imp,
                    'value':          explanation['feature_values'][name]['value'],
                    'interpretation': explanation['feature_values'][name]['interpretation'],
                }
                for name, imp in sorted_feats[:10]
                if name in explanation['feature_values']
            ]

            try:
                explanation['chart_base64'] = self._chart(sorted_feats[:10], prediction)
            except Exception as ce:
                print(f"  [Explainer] Chart error: {ce}")

            return explanation

        except Exception as e:
            import traceback; traceback.print_exc()
            print(f"  [Explainer] explain_prediction failed: {e}")
            return None

    # ── Private ───────────────────────────────────────────────────────────────

    def _compute_importance(self, X: np.ndarray, display_names: list):
        """
        Returns (importance_dict, shap_array_or_None).
        Handles both old SHAP (list output) and new SHAP (3D ndarray output).
        """
        if self.explainer is not None:
            try:
                sv = self.explainer.shap_values(X)

                # ── Normalise across SHAP versions ────────────────────────────
                # Old SHAP (<0.40):  list of arrays  [class0(1,n), class1(1,n)]
                # New SHAP (>=0.41): ndarray (1, n_features, 2)  OR  (1, n_features)
                if isinstance(sv, list):
                    # Old style — pick the phishing class (index 1)
                    sv = sv[1] if len(sv) > 1 else sv[0]
                else:
                    sv = np.array(sv)
                    if sv.ndim == 3:
                        # Shape (1, n_features, 2) — take phishing class values
                        sv = sv[0, :, 1]
                    elif sv.ndim == 2:
                        # Shape (1, n_features)
                        sv = sv[0]

                sv = np.array(sv).flatten()

                if len(sv) != self.n_features:
                    raise ValueError(
                        f"SHAP returned {len(sv)} values, expected {self.n_features}"
                    )

                imp = {
                    name: float(abs(v))
                    for name, v in zip(display_names, sv)
                }
                print(f"  [Explainer] SHAP OK — top 3: "
                      f"{sorted(imp.items(), key=lambda x: -x[1])[:3]}")
                return imp, sv

            except Exception as e:
                print(f"  [Explainer] SHAP compute failed: {e} — using heuristic fallback.")

        # ── Heuristic fallback ────────────────────────────────────────────────
        features_flat = X.flatten()
        imp = {}
        for name, val in zip(display_names, features_flat):
            val = float(val)
            if val == 1 and name in SUSPICIOUS_ON_ONE:
                imp[name] = 0.80
            elif val == -1 and name not in SUSPICIOUS_ON_ONE:
                imp[name] = 0.60
            elif val == 1:
                imp[name] = 0.50
            elif val == -1:
                imp[name] = 0.30
            else:
                imp[name] = 0.10

        return imp, None

    def _interpret(self, name: str, value: float) -> str:
        interpretations = {1: 'Suspicious', 0: 'Neutral', -1: 'Safe'}
        return interpretations.get(int(value), 'Neutral')

    def _chart(self, top_features: list, prediction: int) -> str | None:
        names  = [item[0] for item in top_features]
        values = [item[1] * 100 for item in top_features]

        bar_color = '#ef5350' if prediction == 1 else '#66bb6a'
        bg_color  = '#0a192f'

        fig, ax = plt.subplots(figsize=(10, max(4, len(names) * 0.6)))
        fig.patch.set_facecolor(bg_color)
        ax.set_facecolor(bg_color)

        bars = ax.barh(range(len(names)), values, color=bar_color, alpha=0.85,
                       edgecolor='none')

        for bar, val in zip(bars, values):
            ax.text(
                bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                f'{val:.1f}%', va='center', ha='left', color='white', fontsize=9,
            )

        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=10, color='white')
        ax.set_xlabel('Relative Importance (%)', fontsize=11, color='#aaa')
        ax.set_title('Top Features Influencing This Decision',
                     fontsize=13, color='white', pad=14)
        ax.tick_params(colors='#aaa')
        ax.spines[:].set_color('#1e3a5f')
        ax.invert_yaxis()
        ax.set_xlim(0, (max(values) if values else 1) * 1.18)

        plt.tight_layout()
        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=110, bbox_inches='tight',
                    facecolor=bg_color, edgecolor='none')
        buf.seek(0)
        b64 = base64.b64encode(buf.read()).decode('utf-8')
        plt.close(fig)
        return b64