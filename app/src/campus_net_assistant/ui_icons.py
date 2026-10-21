"""Small, consistent line icons drawn at high DPI; no external icon runtime."""
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def icon(kind: str, color: str = "#526b8b") -> QIcon:
    pixmap = QPixmap(40, 40)
    pixmap.setDevicePixelRatio(2)
    pixmap.fill(Qt.transparent)
    p = QPainter(pixmap)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(QPen(QColor(color), 1.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    if kind == "clock":
        p.drawEllipse(QRectF(3, 3, 14, 14))
        p.drawLine(QPointF(10, 6), QPointF(10, 10))
        p.drawLine(QPointF(10, 10), QPointF(13, 12))
    elif kind == "power":
        path = QPainterPath()
        path.arcMoveTo(QRectF(3, 3, 14, 14), 130)
        path.arcTo(QRectF(3, 3, 14, 14), 130, 280)
        p.drawPath(path)
        p.drawLine(QPointF(10, 2), QPointF(10, 9))
    elif kind == "network":
        p.drawRoundedRect(QRectF(3, 3, 14, 10), 2, 2)
        p.drawLine(QPointF(10, 13), QPointF(10, 17))
        p.drawLine(QPointF(6, 17), QPointF(14, 17))
        p.drawLine(QPointF(6, 8), QPointF(8, 8))
        p.drawLine(QPointF(11, 8), QPointF(14, 8))
    elif kind == "settings":
        for x, y in ((5, 7), (10, 13), (15, 6)):
            p.drawLine(QPointF(x, 3), QPointF(x, y-2))
            p.drawEllipse(QRectF(x-2, y-2, 4, 4))
            p.drawLine(QPointF(x, y+2), QPointF(x, 17))
    elif kind == "document":
        path = QPainterPath(QPointF(5, 2))
        for x,y in ((12,2),(16,6),(16,18),(5,18),(5,2)):
            path.lineTo(x,y)
        p.drawPath(path)
        p.drawLine(QPointF(8, 9), QPointF(13, 9))
        p.drawLine(QPointF(8, 13), QPointF(13, 13))
    elif kind == "folder":
        path = QPainterPath(QPointF(2, 5))
        for x,y in ((8,5),(10,7),(18,7),(16,16),(2,16),(2,5)):
            path.lineTo(x,y)
        p.drawPath(path)
    elif kind == "link":
        p.drawRoundedRect(QRectF(2, 7, 9, 6), 3, 3)
        p.drawRoundedRect(QRectF(9, 7, 9, 6), 3, 3)
        p.drawLine(QPointF(7, 10), QPointF(13, 10))
    elif kind == "shield":
        path = QPainterPath(QPointF(10, 2))
        for x,y in ((17,5),(16,12),(10,18),(4,12),(3,5),(10,2)):
            path.lineTo(x,y)
        p.drawPath(path)
        p.drawLine(QPointF(7, 10), QPointF(9, 12))
        p.drawLine(QPointF(9, 12), QPointF(13, 8))
    else:
        p.drawEllipse(QRectF(3,3,14,14))
        p.drawLine(QPointF(10,9),QPointF(10,14))
        p.drawPoint(QPointF(10,6))
    p.end()
    return QIcon(pixmap)
