from django.db.models import F

ANNOTATE_EVENTS_FIELDS = {'created_on': F('created_at'), 'updated_on': F('updated_at')}
EVENTS_FIELDS = frozenset(('id', 'title', 'content', 'address', 'event_date', 'start_time','end_time', 'embed_url', 'slug', 'mentor', 'banner', 'thumbnail', 'meta_title','created_on', 'meta_description', 'meta_keywords', 'og_box', 'twitter_box', 'google_tag_manager_head','google_tag_manager_body', 'updated_on'),)
