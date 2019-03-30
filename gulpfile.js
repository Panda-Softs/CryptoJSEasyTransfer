var gulp = require('gulp'),
    inline = require('gulp-inline'),
    rename = require('gulp-rename'),
    minify = require('gulp-minify'),
    htmlmin = require('gulp-htmlmin');
    
gulp.task('default', function () {
    return gulp.src('src/CryptoJSEasyTransfer.html')
       .pipe(inline({js: [minify]}))
       .pipe(htmlmin({ collapseWhitespace: true }))
       .pipe(rename('CJSET.html'))
	   .pipe(gulp.dest('dist/'));
});