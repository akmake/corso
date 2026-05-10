const globalErrorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack,
    });
  } else {
    // ב-Production נחזיר הודעה נקייה יותר
    if (err.isOperational) {
      res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
      });
    } else {
      // שגיאה לא צפויה (באג)
      console.error('ERROR 💥', err);
      res.status(500).json({
        status: 'error',
        message: 'משהו השתבש, אנא נסה שנית מאוחר יותר',
      });
    }
  }
};

export default globalErrorHandler;