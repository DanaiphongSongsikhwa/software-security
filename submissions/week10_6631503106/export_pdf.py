from pathlib import Path
from xml.sax.saxutils import escape
import re, textwrap
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
base=Path(__file__).resolve().parents[2]
out=base/'output/pdf/Wk10_6631503106_DRAFT.pdf'
out.parent.mkdir(parents=True, exist_ok=True)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
font_dir=Path('/usr/share/fonts/truetype/dejavu')
for name,file in [('LabSans','DejaVuSans.ttf'), ('LabSans-Bold','DejaVuSans-Bold.ttf'), ('LabSans-Oblique','DejaVuSans-Oblique.ttf'), ('LabSans-BoldOblique','DejaVuSans-BoldOblique.ttf'), ('LabMono','DejaVuSansMono.ttf')]:
 pdfmetrics.registerFont(TTFont(name,str(font_dir/file)))
pdfmetrics.registerFontFamily('LabSans', normal='LabSans', bold='LabSans-Bold', italic='LabSans-Oblique', boldItalic='LabSans-BoldOblique')
styles=getSampleStyleSheet()
for style in styles.byName.values():
 if not hasattr(style, 'fontName'): continue
 style.fontName={'Helvetica':'LabSans','Helvetica-Bold':'LabSans-Bold','Helvetica-Oblique':'LabSans-Oblique','Helvetica-BoldOblique':'LabSans-BoldOblique','Times-Roman':'LabSans','Courier':'LabMono'}.get(style.fontName,'LabSans')
styles['Normal'].fontSize=10
styles['Normal'].leading=14
styles['Normal'].spaceAfter=8
styles['Heading1'].fontSize=17
styles['Heading1'].textColor=colors.HexColor('#153b59')
styles['Heading2'].fontSize=13
styles['Heading2'].textColor=colors.HexColor('#153b59')
styles['Heading3'].fontSize=11
for name in ('Heading1', 'Heading2', 'Heading3'):
 styles[name].keepWithNext=True
styles.add(ParagraphStyle(name='CodeSmall', fontName='LabMono', fontSize=7, leading=9, spaceAfter=5, backColor=colors.HexColor('#f2f5f7'), borderPadding=6))
styles.add(ParagraphStyle(name='CellSmall', fontName='LabSans', fontSize=8, leading=11, spaceAfter=0))
def norm(s):
 return s.replace('\u2014','-').replace('\u2013','-').replace('\u2019',"'").replace('\u201c','"').replace('\u201d','"')
def inline(s):
 s=escape(norm(s))
 s=re.sub(r'`([^`]+)`',r'<font name="LabMono">\1</font>',s)
 s=re.sub(r'\*\*([^*]+)\*\*',r'<b>\1</b>',s)
 return s
lines=(base/'submissions/week10_6631503106/Wk10_6631503106.md').read_text().splitlines()
story=[]; i=0
while i<len(lines):
 line=lines[i]
 if line.startswith('```'):
  i+=1; code=[]
  while i<len(lines) and not lines[i].startswith('```'):
   code.extend(textwrap.wrap(norm(lines[i]), width=104, replace_whitespace=False, drop_whitespace=False) or [''])
   i+=1
  # Small line groups allow long raw transcripts to split over pages cleanly.
  for j in range(0,len(code),12):
   story.append(Preformatted('\n'.join(code[j:j+12]),styles['CodeSmall']))
 elif line.startswith('|'):
  rows=[]
  while i<len(lines) and lines[i].startswith('|'):
   cells=[x.strip() for x in lines[i].strip('|').split('|')]
   if not all(re.fullmatch(r'[-: ]+',x) for x in cells):
    rows.append([Paragraph(inline(c), styles['CellSmall']) for c in cells])
   i+=1
  i-=1
  n=len(rows[0]); widths=[(A4[0]-88)/n]*n
  table=Table(rows,colWidths=widths,repeatRows=1,hAlign='LEFT')
  table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e1ebf2')),('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#c5d1d8')),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
  if story and isinstance(story[-1], Paragraph) and story[-1].style.name.startswith('Heading'):
   heading=story.pop()
   story.extend([KeepTogether([heading,table]),Spacer(1,10)])
  else:
   story.extend([KeepTogether([table]),Spacer(1,10)])
 elif line.startswith('#'):
  depth=len(line)-len(line.lstrip('#'))
  story.append(Paragraph(inline(line[depth:].strip()),styles['Heading'+str(min(depth,3))]))
 elif line.strip():
  para=[line.strip()]
  while i+1<len(lines) and lines[i+1].strip() and not lines[i+1].startswith(('#','|','```')):
   i+=1; para.append(lines[i].strip())
  story.append(Paragraph(inline(' '.join(para)),styles['Normal']))
 i+=1
def footer(canvas, doc):
 canvas.saveState(); canvas.setFont('LabSans',8); canvas.setFillColor(colors.HexColor('#516778'))
 canvas.drawString(44,25,'Week 10 | 6631503106 | DRAFT - screenshots pending')
 canvas.drawRightString(A4[0]-44,25,str(doc.page)); canvas.restoreState()
SimpleDocTemplate(str(out),pagesize=A4,rightMargin=44,leftMargin=44,topMargin=38,bottomMargin=44,title='Week 10 API Security - Draft',author='Danaiphong Songsikhwa; AI assistance disclosed').build(story,onFirstPage=footer,onLaterPages=footer)
print(out)
