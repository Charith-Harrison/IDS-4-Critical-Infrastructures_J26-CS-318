"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/excel_exporter.py

Purpose:
    Generates publication-quality, genuine Microsoft Excel (.xlsx) workbooks from
    pandas DataFrames using openpyxl. Formats header rows with academic navy styling,
    auto-fits column widths, applies freeze panes, and provides in-memory BytesIO
    streaming for Flask file downloads.
"""

import io
from typing import Optional, List
import pandas as pd
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter


def export_dataframe_to_excel_buffer(
    df: pd.DataFrame,
    sheet_name: str = "Sheet1",
    columns_to_export: Optional[List[str]] = None
) -> io.BytesIO:
    """
    Exports a pandas DataFrame to an in-memory BytesIO buffer as a styled .xlsx workbook
    using openpyxl.

    Parameters:
        df: Pandas DataFrame containing the data.
        sheet_name: Name of the worksheet (max 31 characters).
        columns_to_export: Optional list of columns to include.

    Returns:
        BytesIO buffer positioned at byte 0 containing valid .xlsx binary stream.
    """
    buffer = io.BytesIO()

    # Select columns
    if columns_to_export:
        valid_cols = [c for c in columns_to_export if c in df.columns]
        export_df = df[valid_cols].copy()
    else:
        export_df = df.copy()

    safe_sheet = sheet_name[:31]

    # Write data using pandas ExcelWriter with openpyxl engine
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        export_df.to_excel(writer, sheet_name=safe_sheet, index=False)
        ws = writer.sheets[safe_sheet]

        # Style header row with professional academic navy
        header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="0F4C81", end_color="0F4C81", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

        thin_border = Border(
            left=Side(style='thin', color='CBD5E1'),
            right=Side(style='thin', color='CBD5E1'),
            top=Side(style='thin', color='CBD5E1'),
            bottom=Side(style='thin', color='CBD5E1')
        )

        ws.row_dimensions[1].height = 24
        for col_idx, cell in enumerate(ws[1], start=1):
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = thin_border

            # Auto-fit column width based on header length and sample content
            col_letter = get_column_letter(col_idx)
            header_len = len(str(cell.value or ""))
            ws.column_dimensions[col_letter].width = min(40, max(12, header_len + 4))

        # Freeze panes on the header row
        ws.freeze_panes = "A2"

    buffer.seek(0)
    return buffer


def export_dataframe_to_excel_file(
    df: pd.DataFrame,
    file_path: str,
    sheet_name: str = "Sheet1",
    columns_to_export: Optional[List[str]] = None
) -> str:
    """
    Exports a DataFrame directly to a designated file path on disk as an Excel .xlsx workbook.
    """
    buffer = export_dataframe_to_excel_buffer(df, sheet_name=sheet_name, columns_to_export=columns_to_export)
    with open(file_path, "wb") as f:
        f.write(buffer.getvalue())
    return file_path
