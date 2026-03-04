"""
Decorators for courseware views.
"""
import functools

from django.shortcuts import redirect
from opaque_keys import InvalidKeyError
from opaque_keys.edx.keys import CourseKey
from openedx_filters.learning.filters import CoursewareViewStarted


def courseware_view_hooks(view_func):
    """
    Decorator that calls the CoursewareViewStarted filter before rendering a courseware view.

    If any pipeline step raises ``CoursewareViewStarted.RedirectToUrl``, the user is
    redirected to that URL. Otherwise, the original view is rendered normally.

    Usage::

        @courseware_view_hooks
        def my_view(request, course_id, ...):
            ...

    Works with both function-based views and ``method_decorator``-wrapped class-based views.
    The decorator reads the ``course_id`` keyword argument from the view's URL kwargs.
    """
    @functools.wraps(view_func)
    def _wrapper(*args, **kwargs):
        course_id = kwargs.get('course_id')
        if not course_id:
            # Skip unsupported view which has a missing course_id.
            return view_func(*args, **kwargs)

        try:
            course_key = CourseKey.from_string(course_id)
        except InvalidKeyError:
            # Skip bad request which contains a malformed course_id; let the view logic raise an error.
            return view_func(*args, **kwargs)

        try:
            view_name = getattr(view_func, '__name__', '')
            CoursewareViewStarted.run_filter(course_key=course_key, view_name=view_name)
        except CoursewareViewStarted.RedirectToUrl as exc:
            # One of the pipeline steps wants us to block view execution and redirect to a specific URL.
            return redirect(exc.redirect_to)

        return view_func(*args, **kwargs)

    return _wrapper
