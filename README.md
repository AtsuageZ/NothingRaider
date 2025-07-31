# NothingRaider

## 概要
NothingRaiderは、複数のDiscordアカウントを使った自動化・管理・スパム・検証・各種バイパスなど多機能なGUIツールです。

## 主な特徴
- Discordサーバーへの自動参加・退出
- メッセージ・スパム・マスピング・カスタムスパム
- スラッシュコマンド/ボタン/リアクション自動化
- サーバーブースト・プロフィール変更・アバター変更
- サウンドボード・VC参加・音声再生
- GUIによる直感的な操作（CustomTkinter）
- 各種バイパス（オンボーディング、ルール、Bedrock, Ozeu等）

## 使い方
1. 必要な依存パッケージをインストールします：
   ```sh
   pip install -r requirements.txt
   ```
2. `config.toml`や`tokens.txt`など必要なファイルを用意してください。
3. `python NothingRaider.py` で起動します。

## 依存パッケージ
- requests
- websocket-client
- wmi
- tls-client
- toml
- pyaudio
- numpy
- pydub
- customtkinter
- pynacl
- ffmpeg-python

## ライセンス
本ツールはCustom License（非商用・著作権表示必須）です。

## Issue・Pull Request
**IssueやPull Requestは大歓迎です！**
バグ報告・機能要望・改善提案などお気軽にどうぞ。
