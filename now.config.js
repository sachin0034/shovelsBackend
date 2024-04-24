module.exports = {
    builds: [
      {
        src: "app.py",
        use: "@vercel/python",
        config: {
          env: {
            YT_DLP_VERSION: process.env.YT_DLP_VERSION,
            FLASK_APP: process.env.FLASK_APP,
          },
        },
      },
      {
        src: "install-yt-dlp.sh",
        use: "node",
      },
    ],
    routes: [
      {
        src: "/(.*)",
        dest: "app.py",
      },
    ],
  };