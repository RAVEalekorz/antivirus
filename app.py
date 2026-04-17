import requests
from flask import Flask, render_template, request

app = Flask(__name__)

# Вставьте сюда ваш API ключ
VT_API_KEY = 'eddabf2021178d00096ccebe220402bbda1d38e86381a6d99cc04ee855229967'

def check_url(url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    
    # Отправляем URL на анализ
    data = {"url": url}
    response = requests.post(vt_url, data=data, headers=headers)
    
    if response.status_code == 200:
        analysis_id = response.json()['data']['id']
        # Получаем результат анализа
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(result_url, headers=headers)
        stats = analysis_response.json()['data']['attributes']['stats']
        return stats
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    target_url = None
    if request.method == 'POST':
        target_url = request.form.get('url')
        result = check_url(target_url)
    
    return render_template('index.html', result=result, url=target_url)

if __name__ == '__main__':
    app.run(debug=True)
