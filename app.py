import os
import re
import sys
import glob
import warnings

import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

warnings.filterwarnings("ignore", category=FutureWarning)

# ============================================================
# PROJECT PATHS AND IMPORTS
# ============================================================
BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    # No user_analysis.py import required # pyright: ignore[reportMissingImports]
    pass
except ModuleNotFoundError as exc:
    st.error(
        "Could not import src.user_analysis. "
        "Check that src/user_analysis.py exists in your project."
    )
    st.code(str(exc))
    st.stop()

DATA_PATH = os.path.join(
    BASE_DIR, "data", "processed", "detection_results.csv"
)
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
MODEL_PATH = os.path.join(
    BASE_DIR, "models", "isolation_forest.pkl"
)
SCALER_PATH = os.path.join(
    BASE_DIR, "models", "scaler.pkl"
)

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="Zero-Day Attack Detection",
    page_icon="🛡️",
    layout="wide",
)

# ============================================================
# SIDEBAR: AUTO REFRESH
# ============================================================
auto_refresh = st.sidebar.checkbox(
    "Auto-refresh (every 10s)",
    value=False,
)

if auto_refresh:
    st_autorefresh(
        interval=10_000,
        key="dashboard_refresh",
    )

# ============================================================
# ORIGINAL DASHBOARD — TOP SECTION
# ============================================================
st.title("🛡️ Zero-Day Attack Detection")

st.subheader(
    "Behavioral AI Network Security Dashboard"
)

st.write(
    "This dashboard monitors network traffic and identifies "
    "potentially abnormal behavior using an Isolation Forest model."
)

st.header("📤 Analyze Your Own Traffic")

uploaded_file = st.file_uploader(
    "Upload a network traffic CSV (optional)",
    type=["csv"],
    key="original_dashboard_upload",
)

# ============================================================
# LOAD ORIGINAL DETECTION RESULTS
# ============================================================
df = None

if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)
        required_columns = [
            "Status",
            "Risk Level",
            "Label",
            "Anomaly Score",
            "Risk Score",
            "Destination Port",
            "Protocol",
        ]

        missing = [
            col for col in required_columns
            if col not in raw_df.columns
        ]

        if missing:
            st.error(
                "Uploaded CSV is missing required detection columns: "
                + ", ".join(missing)
            )
            st.stop()

        df = raw_df
        st.success("Uploaded detection data loaded successfully.")
        st.success("Uploaded data analyzed successfully.")

    except Exception as exc:
        st.error(
            f"Could not analyze the uploaded file: {exc}"
        )

else:
    try:
        df = pd.read_csv(DATA_PATH)
        st.success("Detection data loaded successfully.")

    except FileNotFoundError:
        st.warning(
            f"Detection results not found at {DATA_PATH}. "
            "Run src/detector.py or upload a traffic CSV. "
            "Dataset comparison below can still be used."
        )

    except Exception as exc:
        st.error(
            f"Could not read detection results: {exc}"
        )

# ============================================================
# ORIGINAL DASHBOARD METRICS
# ============================================================
if df is not None:

    required_columns = [
        "Status",
        "Risk Level",
        "Label",
        "Anomaly Score",
        "Risk Score",
        "Destination Port",
        "Protocol",
    ]

    missing_required = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_required:
        st.error(
            "Detection data is missing required columns: "
            + ", ".join(missing_required)
        )
        df = None

if df is not None:

    total_traffic = len(df)

    normal_traffic = int(
        (df["Status"] == "NORMAL").sum()
    )

    anomalies = int(
        (df["Status"] == "ANOMALY").sum()
    )

    high_risk = int(
        (df["Risk Level"] == "HIGH").sum()
    )

    # ----------------------------
    # Main metrics
    # ----------------------------
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Traffic",
            f"{total_traffic:,}",
        )

    with col2:
        st.metric(
            "Normal Traffic",
            f"{normal_traffic:,}",
        )

    with col3:
        st.metric(
            "Anomalies",
            f"{anomalies:,}",
        )

    with col4:
        st.metric(
            "High Risk Events",
            f"{high_risk:,}",
        )

    # ----------------------------
    # Security status
    # ----------------------------
    st.header("🛡️ Security Status")

    critical_alerts = int(
        (
            (df["Risk Level"] == "HIGH")
            & (df["Status"] == "ANOMALY")
        ).sum()
    )

    medium_risk = int(
        (df["Risk Level"] == "MEDIUM").sum()
    )

    low_risk = int(
        (df["Risk Level"] == "LOW").sum()
    )

    col5, col6, col7 = st.columns(3)

    with col5:
        st.metric(
            "🚨 Critical Alerts",
            critical_alerts,
        )

    with col6:
        st.metric(
            "⚠️ Medium Risk",
            medium_risk,
        )

    with col7:
        st.metric(
            "🟢 Low Risk",
            low_risk,
        )

    # ----------------------------
    # Detection summary
    # ----------------------------
    st.header("Detection Summary")

    summary = pd.DataFrame({
        "Category": [
            "Normal",
            "Anomaly",
            "High Risk",
        ],
        "Count": [
            normal_traffic,
            anomalies,
            high_risk,
        ],
    })

    st.bar_chart(
        summary.set_index("Category")
    )

    # ----------------------------
    # Risk filter
    # ----------------------------
    st.header("🔎 Filter Traffic")

    selected_risk = st.selectbox(
        "Select Risk Level",
        ["ALL", "LOW", "MEDIUM", "HIGH"],
        key="original_risk_filter",
    )

    if selected_risk == "ALL":
        filtered_df = df.copy()
    else:
        filtered_df = df[
            df["Risk Level"] == selected_risk
        ].copy()

    st.write(
        f"Showing {len(filtered_df):,} events"
    )

    st.dataframe(
        filtered_df[
            [
                "Label",
                "Status",
                "Anomaly Score",
                "Risk Score",
                "Risk Level",
            ]
        ].head(100),
        use_container_width=True,
    )

    # ----------------------------
    # Recent detection results
    # ----------------------------
    st.header("Recent Detection Results")

    st.dataframe(
        df[
            [
                "Destination Port",
                "Protocol",
                "Label",
                "Status",
                "Anomaly Score",
                "Risk Score",
                "Risk Level",
            ]
        ].head(50),
        use_container_width=True,
    )

    # ----------------------------
    # AI anomaly score
    # ----------------------------
    st.header("🤖 AI Anomaly Score")

    st.line_chart(
        df[["Anomaly Score"]].head(500)
    )

    # ----------------------------
    # Suspicious traffic
    # ----------------------------
    st.subheader("🔍 Suspicious Network Traffic")

    suspicious = df[
        df["Status"] == "ANOMALY"
    ].copy()

    if not suspicious.empty:
        st.dataframe(
            suspicious[
                [
                    "Destination Port",
                    "Protocol",
                    "Label",
                    "Anomaly Score",
                    "Risk Score",
                    "Risk Level",
                ]
            ].head(50),
            use_container_width=True,
        )
    else:
        st.info(
            "No suspicious traffic detected."
        )

# ============================================================
# DATASET COMPARISON — BOTTOM SECTION
# ============================================================
st.divider()

st.header(
    "📊 CIC-IDS2017 vs CIC-IDS2018 Dataset Comparison"
)

st.caption(
    "Compare dataset structure, missing values, duplicate rows, "
    "label distributions, numeric features and anomaly scores."
)

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def normalize_name(value):
    return (
        str(value)
        .strip()
        .replace("\ufeff", "")
        .lower()
    )


def get_label_column(frame):
    normalized = {
        normalize_name(column): column
        for column in frame.columns
    }

    candidates = [
        "label",
        "attack",
        "attack_type",
        "class",
        "category",
    ]

    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]

    return None


def read_dataset(path, row_limit):
    frame = pd.read_csv(
        path,
        nrows=row_limit,
        low_memory=False,
        encoding_errors="replace",
    )

    frame.columns = [
        str(column).strip().replace("\ufeff", "")
        for column in frame.columns
    ]

    # Convert numeric-looking text columns to numeric.
    for column in frame.columns:

        # FIX: works for both old "object" and new "str" pandas dtypes
        if not pd.api.types.is_numeric_dtype(frame[column]):

            text_values = (
                frame[column]
                .astype(str)
                .str.strip()
            )

            numeric_values = pd.to_numeric(
                text_values,
                errors="coerce",
            )

            nonempty = (
                text_values.ne("")
                & text_values.ne("nan")
            )

            if (
                nonempty.any()
                and numeric_values[nonempty]
                .notna()
                .mean() >= 0.90
            ):
                frame[column] = numeric_values

    return frame


def numeric_feature_columns(frame, label_column):
    excluded_names = {
        "flow id",
        "source ip",
        "src ip",
        "destination ip",
        "dst ip",
        "timestamp",
        "label",
        "attack",
        "attack_type",
        "class",
        "category",
    }

    result = []

    for column in frame.select_dtypes(
        include=[np.number]
    ).columns:

        if column == label_column:
            continue

        if normalize_name(column) in excluded_names:
            continue

        result.append(column)

    return result


def load_saved_model_and_scaler():
    import joblib

    if not os.path.isfile(MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}. "
            "Train your model first."
        )

    if not os.path.isfile(SCALER_PATH):
        raise FileNotFoundError(
            f"Scaler file not found: {SCALER_PATH}. "
            "Train your model first."
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    return model, scaler


# ------------------------------------------------------------
# Column-name matching between CIC-IDS2017 and CIC-IDS2018
# (e.g. "Total Fwd Packets" == "Tot Fwd Pkts")
# ------------------------------------------------------------
_TOKEN_MAP = {
    "pkts": "packets", "pkt": "packets", "packet": "packets",
    "len": "length", "byts": "bytes", "byte": "bytes",
    "tot": "total", "bwd": "backward", "fwd": "forward",
    "cnt": "count", "win": "window", "seg": "segment",
    "avg": "average", "var": "variance", "dst": "destination",
    "src": "source", "blk": "bulk", "flags": "flag",
}

_PRE_REPLACE = [
    ("totlen", "total length"),
    ("fwd byts/b avg", "fwd avg bytes/bulk"),
    ("fwd pkts/b avg", "fwd avg packets/bulk"),
    ("fwd blk rate avg", "fwd avg bulk rate"),
    ("bwd byts/b avg", "bwd avg bytes/bulk"),
    ("bwd pkts/b avg", "bwd avg packets/bulk"),
    ("bwd blk rate avg", "bwd avg bulk rate"),
]


def canonical_feature_name(value):
    text = normalize_name(value)

    for old, new in _PRE_REPLACE:
        text = text.replace(old, new)

    tokens = re.findall(r"[a-z0-9]+", text)
    tokens = [
        _TOKEN_MAP.get(token, token)
        for token in tokens
        if token != "of"
    ]

    # Sorted tokens: "Init_Win_bytes_forward" == "Init Fwd Win Byts"
    return " ".join(sorted(tokens))


def score_frame(frame, model, scaler, expected_features):
    # canonical name -> actual column in this dataframe
    canonical_columns = {}
    for column in frame.columns:
        canonical_columns.setdefault(
            canonical_feature_name(column), column
        )

    X = pd.DataFrame(index=frame.index)
    missing = []

    for feature in expected_features:
        actual = canonical_columns.get(
            canonical_feature_name(feature)
        )

        if actual is None:
            missing.append(feature)
            X[feature] = 0.0
        else:
            X[feature] = frame[actual].to_numpy()

    if missing:
        # Too many missing features => results would be meaningless
        if len(missing) > max(3, int(0.25 * len(expected_features))):
            st.write("Dataset columns available for mapping:")
            st.write(list(frame.columns))
            raise ValueError(
                "Dataset is missing model features: "
                + ", ".join(missing)
            )

        st.warning(
            "These model features were not found in the dataset and "
            "were filled with 0: " + ", ".join(missing)
        )

    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    X = X.replace([np.inf, -np.inf], np.nan)

    for column in X.columns:
        median_value = X[column].median()
        X[column] = X[column].fillna(
            0 if pd.isna(median_value) else median_value
        )

    expected_count = getattr(
        scaler, "n_features_in_", len(expected_features)
    )

    if len(expected_features) != int(expected_count):
        raise ValueError(
            f"Scaler expects {expected_count} features, "
            f"but {len(expected_features)} were provided."
        )

    transformed = scaler.transform(X)
    predictions = model.predict(transformed)
    decision_scores = model.decision_function(transformed)

    result = pd.DataFrame({
        "Anomaly Score (decision_function)": decision_scores,
        "Anomaly Flag": np.where(
            predictions == -1, "Anomaly", "Normal"
        ),
    })

    label_column = get_label_column(frame)

    if label_column:
        result["Dataset Label"] = (
            frame[label_column].astype(str).to_numpy()
        )

    return result


# ============================================================
# FIND DATASET CSV FILES
# ============================================================
csv_paths = sorted(
    glob.glob(
        os.path.join(RAW_DIR, "*.csv")
    ),
    key=lambda path: os.path.basename(path).lower(),
)

csv_names = [
    os.path.basename(path)
    for path in csv_paths
]

path_by_name = {
    os.path.basename(path): path
    for path in csv_paths
}

if len(csv_names) < 2:

    st.warning(
        f"Place both CIC-IDS dataset CSV files inside {RAW_DIR}. "
        "At least two CSV files are required for comparison."
    )

else:

    # Prefer filenames containing 2017 and 2018.
    default_2017 = next(
        (
            i for i, name in enumerate(csv_names)
            if "2017" in name.lower()
        ),
        0,
    )

    default_2018 = next(
        (
            i for i, name in enumerate(csv_names)
            if "2018" in name.lower()
            and i != default_2017
        ),
        next(
            (
                i for i in range(len(csv_names))
                if i != default_2017
            ),
            1,
        ),
    )

    select_left, select_right = st.columns(2)

    with select_left:
        dataset1_name = st.selectbox(
            "Dataset 1 (CIC-IDS2017)",
            csv_names,
            index=default_2017,
            key="comparison_dataset_1",
        )

    available_second = [
        name
        for name in csv_names
        if name != dataset1_name
    ]

    second_index = (
        available_second.index(csv_names[default_2018])
        if csv_names[default_2018] in available_second
        else 0
    )

    with select_right:
        dataset2_name = st.selectbox(
            "Dataset 2 (CIC-IDS2018)",
            available_second,
            index=second_index,
            key="comparison_dataset_2",
        )

    sample_size = st.selectbox(
        "Rows to load from each dataset",
        [1000, 5000, 10000, 25000, 50000],
        index=2,
        format_func=lambda n: f"{n:,} rows",
        key="comparison_row_limit",
    )

    # ========================================================
    # RUN DATASET COMPARISON
    # ========================================================
    if st.button(
        "Run Dataset Comparison",
        type="primary",
        key="run_dataset_comparison",
    ):

        try:
            with st.spinner(
                "Loading datasets and calculating comparisons..."
            ):

                frame1 = read_dataset(
                    path_by_name[dataset1_name],
                    sample_size,
                )

                frame2 = read_dataset(
                    path_by_name[dataset2_name],
                    sample_size,
                )

                st.session_state[
                    "dataset_comparison_result"
                ] = {
                    "dataset1_name": dataset1_name,
                    "dataset2_name": dataset2_name,
                    "sample_size": sample_size,
                    "frame1": frame1,
                    "frame2": frame2,
                }

                st.session_state.pop(
                    "dataset_anomaly_score_result",
                    None,
                )

        except Exception as exc:
            st.error(
                f"Could not load datasets: {exc}"
            )

    # ========================================================
    # DISPLAY CACHED COMPARISON
    # ========================================================
    cached = st.session_state.get(
        "dataset_comparison_result"
    )

    if (
        cached
        and cached["dataset1_name"] == dataset1_name
        and cached["dataset2_name"] == dataset2_name
        and cached["sample_size"] == sample_size
    ):

        frame1 = cached["frame1"]
        frame2 = cached["frame2"]

        # ----------------------------------------------------
        # 1. Dataset overview
        # ----------------------------------------------------
        st.subheader("1. Dataset Overview")

        overview = pd.DataFrame([
            {
                "Dataset": dataset1_name,
                "Rows loaded": len(frame1),
                "Columns": len(frame1.columns),
                "Missing cells": int(
                    frame1.isna().sum().sum()
                ),
                "Duplicate rows in sample": int(
                    frame1.duplicated().sum()
                ),
            },
            {
                "Dataset": dataset2_name,
                "Rows loaded": len(frame2),
                "Columns": len(frame2.columns),
                "Missing cells": int(
                    frame2.isna().sum().sum()
                ),
                "Duplicate rows in sample": int(
                    frame2.duplicated().sum()
                ),
            },
        ])

        st.dataframe(
            overview,
            use_container_width=True,
            hide_index=True,
        )

        # ----------------------------------------------------
        # 2. Missing values
        # ----------------------------------------------------
        st.subheader("2. Missing Values by Column")

        missing1 = frame1.isna().sum()
        missing2 = frame2.isna().sum()

        all_columns = sorted(
            set(frame1.columns) | set(frame2.columns),
            key=str.lower,
        )

        missing_rows = []

        for column in all_columns:
            missing_rows.append({
                "Column": column,
                f"{dataset1_name} missing": int(
                    missing1.get(column, 0)
                ),
                f"{dataset2_name} missing": int(
                    missing2.get(column, 0)
                ),
            })

        missing_table = pd.DataFrame(
            missing_rows
        )

        missing_table = missing_table[
            (
                missing_table[
                    f"{dataset1_name} missing"
                ] > 0
            )
            | (
                missing_table[
                    f"{dataset2_name} missing"
                ] > 0
            )
        ]

        if missing_table.empty:
            st.success(
                "No missing cells were found in the loaded samples."
            )
        else:
            st.dataframe(
                missing_table.sort_values(
                    by=[
                        f"{dataset1_name} missing",
                        f"{dataset2_name} missing",
                    ],
                    ascending=False,
                ),
                use_container_width=True,
                hide_index=True,
            )

        # ----------------------------------------------------
        # 3. Label distribution
        # ----------------------------------------------------
        st.subheader("3. Label Distribution")

        label1 = get_label_column(frame1)
        label2 = get_label_column(frame2)

        label_left, label_right = st.columns(2)

        with label_left:
            st.markdown(f"**{dataset1_name}**")

            if label1:
                counts1 = (
                    frame1[label1]
                    .astype(str)
                    .value_counts(dropna=False)
                    .head(30)
                    .rename_axis("Label")
                    .reset_index(name="Count")
                )

                st.plotly_chart(
                    px.bar(
                        counts1,
                        x="Label",
                        y="Count",
                        title="Label counts",
                    ),
                    use_container_width=True,
                )

                st.dataframe(
                    counts1,
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info(
                    "Could not identify a label column."
                )

        with label_right:
            st.markdown(f"**{dataset2_name}**")

            if label2:
                counts2 = (
                    frame2[label2]
                    .astype(str)
                    .value_counts(dropna=False)
                    .head(30)
                    .rename_axis("Label")
                    .reset_index(name="Count")
                )

                st.plotly_chart(
                    px.bar(
                        counts2,
                        x="Label",
                        y="Count",
                        title="Label counts",
                    ),
                    use_container_width=True,
                )

                st.dataframe(
                    counts2,
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info(
                    "Could not identify a label column."
                )

        # ----------------------------------------------------
        # 4. Common and unique columns
        # ----------------------------------------------------
        st.subheader("4. Common and Unique Columns")

        normalized1 = {
            normalize_name(c): c
            for c in frame1.columns
        }

        normalized2 = {
            normalize_name(c): c
            for c in frame2.columns
        }

        common_keys = sorted(
            set(normalized1) & set(normalized2)
        )

        only1 = sorted(
            set(normalized1) - set(normalized2)
        )

        only2 = sorted(
            set(normalized2) - set(normalized1)
        )

        a, b, c = st.columns(3)

        a.metric(
            "Common columns",
            len(common_keys),
        )

        b.metric(
            f"Only in {dataset1_name}",
            len(only1),
        )

        c.metric(
            f"Only in {dataset2_name}",
            len(only2),
        )

        with st.expander("Show column lists"):
            st.write("**Common columns**")
            st.write([
                normalized1[key]
                for key in common_keys
            ])

            st.write(
                f"**Only in {dataset1_name}**"
            )
            st.write([
                normalized1[key]
                for key in only1
            ])

            st.write(
                f"**Only in {dataset2_name}**"
            )
            st.write([
                normalized2[key]
                for key in only2
            ])

        # ----------------------------------------------------
        # 5. Numeric feature comparison
        # ----------------------------------------------------
        st.subheader("5. Numeric Feature Comparison")

        nums1 = {
            normalize_name(c): c
            for c in numeric_feature_columns(
                frame1,
                label1,
            )
        }

        nums2 = {
            normalize_name(c): c
            for c in numeric_feature_columns(
                frame2,
                label2,
            )
        }

        common_numeric = sorted(
            set(nums1) & set(nums2)
        )

        if common_numeric:

            feature_key = st.selectbox(
                "Choose a shared numeric feature",
                common_numeric,
                format_func=lambda key: normalized1.get(
                    key,
                    nums1[key],
                ),
                key="comparison_numeric_feature",
            )

            col_a = nums1[feature_key]
            col_b = nums2[feature_key]

            stat_rows = []
            plot_rows = []

            for name, current_frame, column in [
                (dataset1_name, frame1, col_a),
                (dataset2_name, frame2, col_b),
            ]:

                values = pd.to_numeric(
                    current_frame[column],
                    errors="coerce",
                ).replace(
                    [np.inf, -np.inf],
                    np.nan,
                ).dropna()

                stat_rows.append({
                    "Dataset": name,
                    "Feature": column,
                    "Valid values": int(values.size),
                    "Mean": (
                        values.mean()
                        if not values.empty else np.nan
                    ),
                    "Median": (
                        values.median()
                        if not values.empty else np.nan
                    ),
                    "Std. deviation": (
                        values.std()
                        if not values.empty else np.nan
                    ),
                    "Minimum": (
                        values.min()
                        if not values.empty else np.nan
                    ),
                    "Maximum": (
                        values.max()
                        if not values.empty else np.nan
                    ),
                })

                plot_rows.append(
                    pd.DataFrame({
                        "Value": values,
                        "Dataset": name,
                    })
                )

            st.dataframe(
                pd.DataFrame(stat_rows),
                use_container_width=True,
                hide_index=True,
            )

            distribution = pd.concat(
                plot_rows,
                ignore_index=True,
            )

            if not distribution.empty:

                st.plotly_chart(
                    px.histogram(
                        distribution,
                        x="Value",
                        color="Dataset",
                        barmode="overlay",
                        opacity=0.6,
                        nbins=40,
                        title=(
                            f"Distribution of {col_a} / {col_b}"
                        ),
                    ),
                    use_container_width=True,
                )

                st.plotly_chart(
                    px.box(
                        distribution,
                        x="Dataset",
                        y="Value",
                        color="Dataset",
                        title=(
                            f"Feature spread: {col_a} / {col_b}"
                        ),
                    ),
                    use_container_width=True,
                )

        else:
            st.info(
                "No shared numeric feature columns were detected."
            )

        # ----------------------------------------------------
        # Dataset overview download
        # ----------------------------------------------------
        st.download_button(
            "Download Dataset Comparison Overview (CSV)",
            data=overview.to_csv(
                index=False
            ).encode("utf-8"),
            file_name="cic_ids_dataset_comparison.csv",
            mime="text/csv",
            key="download_dataset_comparison",
        )

        # ====================================================
        # 6. ANOMALY SCORE COMPARISON
        # ====================================================
        st.divider()

        st.subheader(
            "6. 🤖 Anomaly Score Comparison"
        )

        st.caption(
            "Uses the saved Isolation Forest and scaler. Lower "
            "decision_function scores indicate more anomalous samples. "
            "These are model predictions, not verified attack labels."
        )

        if st.button(
            "Calculate Anomaly Scores for Both Datasets",
            type="primary",
            key="calculate_dataset_anomaly_scores",
        ):

            try:
                with st.spinner(
                    "Applying the saved model to both samples..."
                ):

                    model, scaler = (
                        load_saved_model_and_scaler()
                    )

                    scaler_features = getattr(
                        scaler,
                        "feature_names_in_",
                        None,
                    )

                    model_features = getattr(
                        model,
                        "feature_names_in_",
                        None,
                    )

                    # Get the feature names and preserve the training order.
                    if scaler_features is not None:
                        expected_features = [
                            str(feature) for feature in scaler_features
                        ]

                    elif model_features is not None:
                        expected_features = [
                            str(feature) for feature in model_features
                        ]

                    else:
                        expected_count = getattr(
                            scaler,
                            "n_features_in_",
                            getattr(model, "n_features_in_", None),
                        )

                        if expected_count is None:
                            raise ValueError(
                                "Cannot determine the model's expected feature count."
                            )

                        # FIX: keep the original column order of dataset 1
                        # instead of alphabetical order.
                        common_set = set(common_numeric)
                        expected_features = [
                            column for column in frame1.columns
                            if normalize_name(column) in common_set
                        ]

                        if len(expected_features) != int(expected_count):
                            raise ValueError(
                                f"Model expects {expected_count} features, but "
                                f"{len(expected_features)} common numeric features "
                                "are available. The original feature order is unknown."
                            )

                    scored1 = score_frame(
                        frame1,
                        model,
                        scaler,
                        expected_features,
                    )

                    scored2 = score_frame(
                        frame2,
                        model,
                        scaler,
                        expected_features,
                    )

                    scored1.insert(
                        0,
                        "Dataset",
                        dataset1_name,
                    )

                    scored2.insert(
                        0,
                        "Dataset",
                        dataset2_name,
                    )

                    st.session_state[
                        "dataset_anomaly_score_result"
                    ] = {
                        "dataset1_name": dataset1_name,
                        "dataset2_name": dataset2_name,
                        "scored1": scored1,
                        "scored2": scored2,
                    }

            except Exception as exc:
                st.error(
                    f"Could not calculate anomaly scores: {exc}"
                )
                st.exception(exc)

        # ----------------------------------------------------
        # Display saved anomaly score results
        # ----------------------------------------------------
        score_cache = st.session_state.get(
            "dataset_anomaly_score_result"
        )

        if (
            score_cache
            and score_cache["dataset1_name"] == dataset1_name
            and score_cache["dataset2_name"] == dataset2_name
        ):

            scored1 = score_cache["scored1"]
            scored2 = score_cache["scored2"]

            score_column = (
                "Anomaly Score (decision_function)"
            )

            score_summaries = []

            for name, result in [
                (dataset1_name, scored1),
                (dataset2_name, scored2),
            ]:

                values = pd.to_numeric(
                    result[score_column],
                    errors="coerce",
                ).dropna()

                anomaly_mask = result[
                    "Anomaly Flag"
                ].eq("Anomaly")

                score_summaries.append({
                    "Dataset": name,
                    "Rows scored": int(values.size),
                    "Mean score": (
                        values.mean()
                        if not values.empty else np.nan
                    ),
                    "Median score": (
                        values.median()
                        if not values.empty else np.nan
                    ),
                    "Minimum score": (
                        values.min()
                        if not values.empty else np.nan
                    ),
                    "Maximum score": (
                        values.max()
                        if not values.empty else np.nan
                    ),
                    "Anomalies flagged": int(
                        anomaly_mask.sum()
                    ),
                    "Anomaly percentage": (
                        float(anomaly_mask.mean() * 100)
                        if len(anomaly_mask) else 0.0
                    ),
                })

            score_summary_df = pd.DataFrame(
                score_summaries
            )

            st.dataframe(
                score_summary_df,
                use_container_width=True,
                hide_index=True,
            )

            metric1, metric2 = st.columns(2)

            metric1.metric(
                f"{dataset1_name} flagged anomalous",
                (
                    f"{score_summary_df.iloc[0]['Anomaly percentage']:.2f}%"
                ),
            )

            metric2.metric(
                f"{dataset2_name} flagged anomalous",
                (
                    f"{score_summary_df.iloc[1]['Anomaly percentage']:.2f}%"
                ),
            )

            # Combine row-level results
            combined_scores = pd.concat(
                [scored1, scored2],
                ignore_index=True,
            )

            combined_scores[score_column] = pd.to_numeric(
                combined_scores[score_column],
                errors="coerce",
            )

            combined_scores = combined_scores.replace(
                [np.inf, -np.inf],
                np.nan,
            ).dropna(
                subset=[score_column]
            )

            # Histogram
            if not combined_scores.empty:

                st.plotly_chart(
                    px.histogram(
                        combined_scores,
                        x=score_column,
                        color="Dataset",
                        barmode="overlay",
                        opacity=0.6,
                        nbins=40,
                        title=(
                            "Isolation Forest Anomaly Score Distribution"
                        ),
                    ),
                    use_container_width=True,
                )

                # Box plot
                st.plotly_chart(
                    px.box(
                        combined_scores,
                        x="Dataset",
                        y=score_column,
                        color="Dataset",
                        title="Anomaly Score Spread by Dataset",
                    ),
                    use_container_width=True,
                )

            st.dataframe(
                combined_scores.head(100),
                use_container_width=True,
                hide_index=True,
            )

            # Download row-level results
            st.download_button(
                "Download Row-Level Anomaly Scores (CSV)",
                data=combined_scores.to_csv(
                    index=False
                ).encode("utf-8"),
                file_name="cic_ids_anomaly_scores.csv",
                mime="text/csv",
                key="download_anomaly_scores",
            )

# ============================================================
# FOOTER
# ============================================================
st.divider()

st.caption(
    "Zero-Day Attack Detection • Original dashboard above; "
    "dataset comparison and anomaly scoring below."
)