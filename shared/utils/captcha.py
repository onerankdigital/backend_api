"""
CAPTCHA generation and validation utilities
"""
import secrets
import string
import hashlib
import base64
from io import BytesIO
from typing import Tuple, Optional
import os

# Try to import PIL/Pillow
try:
    from PIL import Image, ImageDraw, ImageFont
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    Image = None
    ImageDraw = None
    ImageFont = None

# Try to use a font if available, otherwise use default
DEFAULT_FONT = None
if PILLOW_AVAILABLE:
    try:
        # Try to use a system font
        font_path = None
        if os.name == 'nt':  # Windows
            font_path = "C:/Windows/Fonts/arial.ttf"
        elif os.name == 'posix':  # Linux/Mac
            font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        
        if font_path and os.path.exists(font_path):
            DEFAULT_FONT = ImageFont.truetype(font_path, 28)
        else:
            DEFAULT_FONT = ImageFont.load_default()
    except Exception as e:
        try:
            DEFAULT_FONT = ImageFont.load_default()
        except:
            DEFAULT_FONT = None


def generate_captcha_text(length: int = 5) -> str:
    """Generate random CAPTCHA text (letters and numbers, excluding confusing characters)"""
    # Use only uppercase letters and numbers, excluding 0, O, I, 1 (confusing)
    chars = string.ascii_uppercase.replace('O', '').replace('I', '') + '23456789'
    return ''.join(secrets.choice(chars) for _ in range(length))


def generate_captcha_image(text: str, width: int = 150, height: int = 50) -> bytes:
    """Generate CAPTCHA image as PNG bytes"""
    if not PILLOW_AVAILABLE:
        raise ImportError("Pillow is not installed. Please install it with: pip install Pillow")
    
    try:
        # Create image with light background
        img = Image.new('RGB', (width, height), color=(240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Draw some noise lines
        for _ in range(5):
            x1 = secrets.randbelow(width)
            y1 = secrets.randbelow(height)
            x2 = secrets.randbelow(width)
            y2 = secrets.randbelow(height)
            draw.line([(x1, y1), (x2, y2)], fill=(200, 200, 200), width=1)
        
        # Draw some noise dots
        for _ in range(50):
            x = secrets.randbelow(width)
            y = secrets.randbelow(height)
            draw.point((x, y), fill=(180, 180, 180))
        
        # Calculate text position (centered) - simplified approach
        char_width = width // (len(text) + 1)
        start_x = char_width
        y = (height - 30) // 2
        
        # Draw text with slight variation
        for i, char in enumerate(text):
            char_x = start_x + (i * char_width)
            # Random color (dark but not black)
            color = (
                secrets.randbelow(50) + 50,  # 50-100
                secrets.randbelow(50) + 50,
                secrets.randbelow(50) + 50
            )
            
            # Simple text drawing without rotation for reliability
            try:
                if DEFAULT_FONT:
                    draw.text((char_x, y), char, font=DEFAULT_FONT, fill=color)
                else:
                    draw.text((char_x, y), char, fill=color)
            except Exception as e:
                # Fallback to simple text
                draw.text((char_x, y), char, fill=color)
        
        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        return buffer.getvalue()
    except Exception as e:
        # If image generation fails, raise with helpful message
        raise Exception(f"Failed to generate CAPTCHA image: {str(e)}")


def create_captcha(captcha_id: str, text: str) -> Tuple[str, bytes]:
    """Create CAPTCHA image and return base64 encoded image"""
    image_bytes = generate_captcha_image(text)
    image_base64 = base64.b64encode(image_bytes).decode('utf-8')
    image_data_url = f"data:image/png;base64,{image_base64}"
    return image_data_url, image_bytes


def hash_captcha_text(text: str) -> str:
    """Hash CAPTCHA text for storage (one-way hash)"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

