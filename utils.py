#This file is part galatea blueprint for Flask.
#The COPYRIGHT file at the top level of this repository contains
#the full copyright notices and license terms.
from flask import current_app
from trytond.config import config as tryton_config
from slug import slug
from PIL import Image
import os

def get_tryton_language(lang):
    '''
    Convert language to tryton languages
    Example: ca -> ca_ES
    '''
    languages = current_app.config.get('ACCEPT_LANGUAGES')
    for k, v in languages.iteritems():
        l = k.split('_')[0]
        if l == lang:
            return k

def get_tryton_locale(lang):
    '''
    Get locale options from lang
    '''
    languages = {
        'en': {'date': '%m/%d/%Y', 'thousands_sep': ',', 'decimal_point': '.',
            'grouping': [3, 3, 0]},
        'ca': {'date': '%d/%m/%Y', 'thousands_sep': ' ', 'decimal_point': ',',
            'grouping': [3, 3, 0]},
        'es': {'date': '%d/%m/%Y', 'thousands_sep': ',', 'decimal_point': '.',
            'grouping': [3, 3, 0]},
        'fr': {'date': '%d.%m.%Y', 'thousands_sep': ' ', 'decimal_point': ',',
            'grouping': [3, 0]},
        }
    if languages.get(lang):
        return languages.get(lang)
    return languages.get('en')

def slugify(value):
    """Convert value to slug: az09 and replace spaces by -"""
    try:
        if isinstance(value, unicode):
            name = slug(value)
        else:
            name = slug(unicode(value, 'UTF-8'))
    except:
        name = ''
    return name

def thumbnail(filename, thumbname, size, crop=None, quality=85):
    '''Create thumbnail image

    :param filename: image digest - '2566a0e6538be8e094431ff46ae58950'
    :param thumbname: file name image - 'test.jpg'
    :param size: size thumb - '100x100'
    :param crop: crop thumb - top, middle, bottom or None
    :param quality: JPEG quality 1-100
    :return Thumb URL
    '''
    def _get_name(name, fm, *args):
        for v in args:
            if v:
                name += '_%s' % v
        name += fm
        return name

    width, height = [int(x) for x in size.split('x')]
    name, fm = os.path.splitext(thumbname)

    miniature = _get_name(name, fm, size, crop, quality)

    original_filename = os.path.join(tryton_config.get('database', 'path'), current_app.config['TRYTON_DATABASE'], filename[0:2], filename[2:4], filename)
    thumb_filename = os.path.join(current_app.config['MEDIA_CACHE_FOLDER'], miniature)

    thumb_url = os.path.join(current_app.config['MEDIA_CACHE_URL'], miniature)

    if os.path.exists(thumb_filename):
        return thumb_url
    else:
        size = (width, height)

        try:
            img = Image.open(original_filename)
        except IOError:
            return current_app.config['BASE_IMAGE']

        if crop:
            img_ratio = img.size[0] / float(img.size[1])
            ratio = size[0] / float(size[1])

            #The image is scaled/cropped vertically or horizontally depending on the ratio
            if ratio > img_ratio:
                img = img.resize((size[0], size[0] * img.size[1] / img.size[0]), Image.ANTIALIAS)
                # Crop in the top, middle or bottom
                if crop == 'top':
                    box = (0, 0, img.size[0], size[1])
                elif crop == 'bottom':
                    box = (0, img.size[1] - size[1], img.size[0], img.size[1])
                else :
                    box = (0, (img.size[1] - size[1]) / 2, img.size[0], (img.size[1] + size[1]) / 2)
                img = img.crop(box)
            elif ratio < img_ratio:
                img = img.resize((size[1] * img.size[0] / img.size[1], size[1]), Image.ANTIALIAS)
                # Crop in the top, middle or bottom
                if crop == 'top':
                    box = (0, 0, size[0], img.size[1])
                elif crop == 'bottom':
                    box = (img.size[0] - size[0], 0, img.size[0], img.size[1])
                else :
                    box = ((img.size[0] - size[0]) / 2, 0, (img.size[0] + size[0]) / 2, img.size[1])
                img = img.crop(box)
        else:
            img.thumbnail(size)

        img.save(thumb_filename, img.format, quality=quality)

        return thumb_url
